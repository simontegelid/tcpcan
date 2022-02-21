# tcpcan

A socketCAN on TCP client/server

## Usage

```
usage: tcpcan.py [-h] [--host HOST] [--port PORT] [--serve] [-v] canif

Tunnel SocketCAN on TCP.

positional arguments:
  canif          SocketCAN interface

optional arguments:
  -h, --help     show this help message and exit
  --host HOST    TCP host (default: localhost)
  --port PORT    TCP port (default: 20010)
  --serve
  -v, --verbose
```

### Server

```
tcpcan vcan0 --serve
```

### Client

```
tcpcan vcan0
```

## Protocol

This section describes the protocol used by tcpcan. Every message has a two
byte header containing a prefix (1 byte) and a length (1 byte). The protocol is
big endian if nothing else is stated. A connection always starts with a
protocol version negotiation using the Protocol version message. No other
messages than Protocol version messages must be sent before a version agreement
has been met.

### Message header

```
| --------------- | ----------------- | --------------------------------- |
| Prefix (1 byte) | Length N (1 byte) | Prefix specific payload (N bytes) |
| --------------- | ----------------- | --------------------------------- |
```

### Messages

| Prefix | Format | Description                                            | Supported in version |
| ------ | ------ | ------------------------------------------------------ | -------------------- |
| v      | I      | Protocol version                                       | 1                    |
| d      | B*     | SocketCAN data, 16 B (can_frame) or 72 B (canfd_frame) | 1                    |

### Protocol version negotiation

A client initiates the negotiation by proposing a protocol version it supports,
typically its highest supported version. The server responds with either the
same version number as an acknowledgement that an agreement has been met or it
proposes a lower version number. If the version number is lowered the
negotiation continue until an agreement is made. If the version reaches 0, no
agreement could be made and the connection is terminated. A communicating party
must not respond to a Protocol version message if it contains the same version
number as the party itself has proposed earlier.
