#!/usr/bin/env python3
"""Generate input.pcap: one HTTP/2 transaction on a single stream, with the
request inspected before the response, for a `=>` rule that has one HTTP/2
buffer per direction (Redmine #9087).

Written with the HTTP/2 framing and HPACK by hand (stdlib only, no python
`h2` package): only literal-without-indexing header fields and the frame
types needed for one request/response are encoded, which keeps the pcap
reproducible without dependencies.

Layout (pcap_cnt):
  1-3   TCP handshake
  4     C: connection preface + SETTINGS
  5     S: SETTINGS
  6     C: HEADERS[1] POST /upload (content-length: 6)
  7     C: DATA[1] "secret" + END_STREAM, request completes here
  8     S: HEADERS[1] :status 200 OK + END_STREAM, response completes here
  9-11  teardown

The toserver half (`http.uri`, `http.request_body`) is inspected at 6 and 7,
the toclient half (`http.stat_code`) at 8.
"""

import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

ETH_C, ETH_S = "00:11:22:33:44:55", "66:77:88:99:aa:bb"
IP_C, IP_S = "192.168.0.1", "192.168.0.2"
PORT_C, PORT_S = 44444, 80

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
BODY = b"secret"

FRAME_DATA = 0
FRAME_HEADERS = 1
FRAME_SETTINGS = 4
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4


def frame(ftype, flags, stream_id, payload=b""):
    return (
        struct.pack(">I", len(payload))[1:]
        + bytes([ftype, flags])
        + struct.pack(">I", stream_id)
        + payload
    )


def hpack(fields):
    """literal header field without indexing, never huffman encoded"""

    def lit(value):
        assert len(value) < 127
        return bytes([len(value)]) + value

    out = b""
    for name, value in fields:
        out += b"\x00" + lit(name.encode()) + lit(value.encode())
    return out


def settings():
    # empty SETTINGS frame: default window of 65535 and header table of 4096
    return frame(FRAME_SETTINGS, 0, 0)


REQ_HEADERS = hpack(
    [
        (":method", "POST"),
        (":scheme", "http"),
        (":authority", "example.com"),
        (":path", "/upload"),
        ("content-length", "6"),
    ]
)
RESP_HEADERS = hpack([(":status", "200"), ("content-length", "0")])


def c(flags, seq, ack, load=None):
    pkt = Ether(src=ETH_C, dst=ETH_S) / IP(src=IP_C, dst=IP_S) / TCP(
        sport=PORT_C, dport=PORT_S, flags=flags, seq=seq, ack=ack
    )
    return pkt / Raw(load=load) if load else pkt


def s(flags, seq, ack, load=None):
    pkt = Ether(src=ETH_S, dst=ETH_C) / IP(src=IP_S, dst=IP_C) / TCP(
        sport=PORT_S, dport=PORT_C, flags=flags, seq=seq, ack=ack
    )
    return pkt / Raw(load=load) if load else pkt


def main():
    cpre = PREFACE + settings()
    chdrs = frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, REQ_HEADERS)
    cdata = frame(FRAME_DATA, FLAG_END_STREAM, 1, BODY)
    client_bytes = cpre + chdrs + cdata
    shead = settings()
    shdrs = frame(FRAME_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1, RESP_HEADERS)
    server_bytes = shead + shdrs

    packets = [
        c("S", 0, 0),
        s("SA", 0, 1),
        c("A", 1, 1),
        c("PA", 1, 1, cpre),
        s("PA", 1, 1 + len(cpre), shead),
        c("PA", 1 + len(cpre), 1 + len(shead), chdrs),
        c("PA", 1 + len(cpre) + len(chdrs), 1 + len(shead), cdata),
        s("PA", 1 + len(shead), 1 + len(cpre) + len(chdrs) + len(cdata), shdrs),
        c("FA", 1 + len(client_bytes), 1 + len(server_bytes)),
        s("FA", 1 + len(server_bytes), 2 + len(client_bytes)),
        c("A", 2 + len(client_bytes), 2 + len(server_bytes)),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = i * 0.01

    wrpcap("input.pcap", packets)
    print(f"wrote input.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()
