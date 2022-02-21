import socket
import argparse
import time
import selectors
import logging
import struct

_HEADER_FMT = (
    ">cb"  # prefix char + payload len (not including len(prefix char + payload len))
)
_HEADER_LEN = 2  # len(prefix char + payload len)

_VERSION_PREFIX = b"v"
_DATA_PREFIX = b"d"

_LOGGER = logging.getLogger(name="tcpcan")

_MAX_SUPPORTED_VERSION = 1


class _ConnectionClosed(ConnectionError):
    pass


class _BridgeInstance:
    def __init__(
        self,
        sel: selectors.BaseSelector,
        tcp_socket: socket.socket,
        canif: str,
    ):
        self.sel = sel
        self.tcp_socket = tcp_socket
        self.canif = canif
        self.can_socket = None

        self.proposed_version = None
        self.agreed_version = None

        self._prepare_bridge()

    def _prepare_bridge(self):
        self.tcp_socket.setblocking(False)
        can_socket = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        can_socket.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FD_FRAMES, 1)
        can_socket.bind((self.canif,))
        can_socket.setblocking(False)
        self.sel.register(
            self.tcp_socket,
            selectors.EVENT_READ,
            (self._tcp_reader, ()),
        )
        self.sel.register(can_socket, selectors.EVENT_READ, (self._can_reader, ()))
        self.can_socket = can_socket

    @staticmethod
    def _pack_header(prefix: str, payload_len: int):
        if payload_len > 255:
            raise RuntimeError("Too large payload length")
        return struct.pack(_HEADER_FMT, prefix, payload_len)

    @staticmethod
    def _unpack_header(hdr_data: bytes):
        prefix, length = struct.unpack(_HEADER_FMT, hdr_data)
        return prefix, length

    @staticmethod
    def _pack_version_message(version: int):
        return _BridgeInstance._pack_header(_VERSION_PREFIX, 4) + struct.pack(
            ">I", version
        )

    @staticmethod
    def _pack_data_message(data: bytes):
        return _BridgeInstance._pack_header(_DATA_PREFIX, len(data)) + data

    @staticmethod
    def _unpack_version_payload(version_msg: bytes):
        (version,) = struct.unpack(">I", version_msg)
        return version

    def _recv_message(self):
        try:
            hdr = self.tcp_socket.recv(_HEADER_LEN)
        except ConnectionResetError:
            self._shutdown()

        if len(hdr) < _HEADER_LEN:
            self._shutdown()

        prefix, length = self._unpack_header(hdr)
        payload = self.tcp_socket.recv(length)
        if len(payload) < length:
            self._shutdown()
        return prefix, payload

    def _shutdown(self):
        _LOGGER.debug("Shutdown %s, %s", self.tcp_socket, self.can_socket)
        self.sel.unregister(self.tcp_socket)
        self.tcp_socket.close()
        self.sel.unregister(self.can_socket)
        self.can_socket.close()
        raise _ConnectionClosed

    def negotiate_version(self):
        self._propose_version(_MAX_SUPPORTED_VERSION)

    def _propose_version(self, version):
        _LOGGER.debug("Propose version: %d", version)
        self.proposed_version = version
        version_msg = self._pack_version_message(version)
        self.tcp_socket.sendall(version_msg)

    def _tcp_reader(
        self,
        sock: socket.socket,  # should be same socket as self.tcp_socket
        mask,
        sel,
    ):
        if self.agreed_version is None:
            prefix, payload = self._recv_message()
            if prefix != _VERSION_PREFIX:
                _LOGGER.warning("Expected version message, got '%c'", prefix.decode())
                self._shutdown()

            version = self._unpack_version_payload(payload)
            _LOGGER.debug("Got version negotiation: %d", version)
            if version == self.proposed_version:
                # Received ACK on proposed version. We have an agreement.
                _LOGGER.info("Agreed version: %d", version)
                self.agreed_version = version
                return

            if version == _MAX_SUPPORTED_VERSION:
                # Ack the version request if supported.
                self._propose_version(version)
                self.agreed_version = version

            # Handle version downgrade here when needed.
            else:
                _LOGGER.warning("Version negotiation failed (%d)", version)
                self._shutdown()

            return

        # If agreed version:
        prefix, payload = self._recv_message()
        _LOGGER.debug("Got %d bytes on TCP" % len(payload))

        if prefix != _DATA_PREFIX:
            _LOGGER.error("Got unexpected message %c", prefix)
            self._shutdown()

        try:
            self.can_socket.send(payload)
        except Exception as e:
            _LOGGER.error("CAN send fail: %s" % e)

    def _can_reader(
        self,
        sock: socket.socket,
        mask,
        sel,
    ):
        if self.agreed_version is None:
            # Drop can frames until version is negotiated.
            return

        can_frame = self.can_socket.recv(1024)

        _LOGGER.debug("Got %d bytes on CAN" % len(can_frame))

        if len(can_frame) <= 0:
            _LOGGER.info("Close CAN")
            self._shutdown()

        if len(can_frame) not in [16, 72]:
            _LOGGER.error("Unexpected can frame length (%d B)" % len(can_frame))
            return

        tcp_data = self._pack_data_message(can_frame)
        try:
            self.tcp_socket.sendall(tcp_data)
        except Exception as e:
            _LOGGER.error("TCP send fail: %s" % e)


def _run_bridge(sel) -> bool:
    while True:
        try:
            events = sel.select()
        except KeyboardInterrupt:
            sel.close()
            return False
        for key, mask in events:
            callback, args = key.data
            try:
                callback(key.fileobj, mask, sel, *args)
            except _ConnectionClosed:
                pass
        if len(sel.get_map()) == 0:
            _LOGGER.debug("Nothing left to wait for")
            return True


def _start(host: str, port: int, canif: str, serve: bool, no_retry: bool):
    sel = selectors.DefaultSelector()
    if serve:

        def accept(tcp_socket, mask, sel, canif):
            tcp_socket, addr = tcp_socket.accept()
            _LOGGER.info("Accepted %s:%d", addr[0], addr[1])
            _BridgeInstance(sel, tcp_socket, canif)

        tcp_socket = socket.socket()
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((host, port))
        tcp_socket.listen(100)
        _LOGGER.info("Listening on %s:%d", host, port)
        tcp_socket.setblocking(False)
        sel.register(tcp_socket, selectors.EVENT_READ, (accept, (canif,)))

        _run_bridge(sel)
    else:
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
                try:
                    _LOGGER.debug("Connecting to %s:%d" % (host, port))
                    tcp_socket.connect((host, port))
                except ConnectionRefusedError:
                    _LOGGER.error("Connection refused")
                else:
                    _LOGGER.info("Connected to %s:%d" % (host, port))
                    b = _BridgeInstance(sel, tcp_socket, canif)
                    b.negotiate_version()

                    keep_going = _run_bridge(sel)
                    if not keep_going:
                        break
                if no_retry:
                    break
                time.sleep(1)


def main():
    parser = argparse.ArgumentParser(
        description="Tunnel SocketCAN on TCP.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("canif", help="SocketCAN interface")
    parser.add_argument("--host", default="localhost", help="TCP host")
    parser.add_argument("--port", default=20010, type=int, help="TCP port")
    parser.add_argument(
        "--serve", action="store_true", default=False, help="Run as server"
    )
    parser.add_argument(
        "--no-retry",
        action="store_true",
        default=False,
        help="Do not retry if client connection fail",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False, help="Verbose output"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    _start(args.host, args.port, args.canif, args.serve, args.no_retry)
