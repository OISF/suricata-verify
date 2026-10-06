#!/usr/bin/env python3
"""
Generate input.pcap for the http2-padded-continuation SV test.

Ticket: 8840 (http2 continuation frame reassembly).

A PADDED header frame carries its padding inside the FIRST physical frame:
[Pad Length][Priority?][first fragment part][Padding] (RFC 9113 6.2.3 field
layout; nghttp2 sender: "We arranged padding so that it is included in the
first frame completely"). The CONTINUATION frames carry only field block
fragment bytes.

The pcap has two HTTP/2 connections, each with a 165-byte response field
block split over HEADERS + 2x CONTINUATION with the PADDED flag set:

  connection 1 (port 443): PADDED response only.
  connection 2 (port 444): PADDED response, plus a single-frame
    PADDED + PRIORITY request HEADERS frame (PRIORITY on the request side:
    http2.response has no 'priority' property in etc/schema.json, so a
    PRIORITY response HEADERS frame fails eve schema validation).

Per-connection layout (server -> client, stream 1):
  HEADERS        flags=PADDED|END_STREAM
                 payload=[padlen][P1: 60B][padlen pad bytes]
  CONTINUATION   flags=0            payload=P2 (60B)
  CONTINUATION   flags=END_HEADERS  payload=P3 (45B)

Connection 2 request (client -> server, stream 1):
  HEADERS        flags=PADDED|PRIORITY|END_HEADERS|END_STREAM
                 payload=[padlen: 5][prio: 5][request block: 28B][5 pad bytes]

Response HPACK block (165B, no huffman) = P1 || P2 || P3:
  0x88                                  :status 200
  10x 0x10 0x01 'x' 0x0a 'A'*10         literal w/o indexing: x: AAAAAAAAAA
  0x10 0x0a 'x-splitpad' 0x0b <value>   marker: x-splitpad: splitpad-cN

Request block (28B): 82 84 86 + :authority example.com

Validate:
  tshark -r input.pcap -d tcp.port==443,http2 -d tcp.port==444,http2 -Y http2
Both connections must dissect as
"SETTINGS[0], HEADERS[1]: 200 OK, CONTINUATION[1], CONTINUATION[1]"
and the full header section (including the x-splitpad marker) must decode.
"""
import struct

from scapy.all import IP, Raw, TCP, wrpcap


def h2(length: int, ftype: int, flags: int, sid: int, payload: bytes) -> bytes:
    assert length == len(payload)
    return (
        struct.pack(">I", length)[1:]
        + bytes([ftype, flags])
        + struct.pack(">I", sid & 0x7FFFFFFF)
        + payload
    )


def response_block(value: bytes) -> bytes:
    assert len(value) == 11
    filler = b"".join(b"\x10\x01x\x0a" + b"A" * 10 for _ in range(10))
    marker = b"\x10\x0ax-splitpad\x0b" + value
    return b"\x88" + filler + marker


def request_block() -> bytes:
    host = b"example.com"
    return (
        b"\x82\x84\x86"
        + b"\x40\x0a" + b":authority"  # :authority literal, incremental indexing
        + bytes([len(host)]) + host
    )


def build_connection(cip: str, sip: str, cport: int, sport: int,
                     padlen: int, priority: bytes, c_isn: int, s_isn: int,
                     marker_value: bytes,
                     req_flags: int = 0x05, req_prio: bytes = b"",
                     req_padlen: int = 0):
    block = response_block(marker_value)
    assert len(block) == 165
    p1, p2, p3 = block[:60], block[60:120], block[120:165]

    # padding must fit inside the first physical frame
    assert padlen <= len(p1)

    flags = 0x09  # PADDED | END_STREAM
    head_payload = bytes([padlen]) + priority + p1 + b"\x00" * padlen
    if priority:
        flags |= 0x20  # PRIORITY

    req = request_block()
    if req_prio or req_padlen:
        req_payload = bytes([req_padlen]) + req_prio + req + b"\x00" * req_padlen
    else:
        req_payload = req
    # empty SETTINGS frame: length 0, type 4
    settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    cdata = (
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        + settings
        + h2(len(req_payload), 0x01, req_flags, 1, req_payload)
    )
    sdata = (
        settings
        + h2(len(head_payload), 0x01, flags, 1, head_payload)
        + h2(len(p2), 0x09, 0x00, 1, p2)
        + h2(len(p3), 0x09, 0x04, 1, p3)
    )

    ip_c = IP(src=cip, dst=sip)
    ip_s = IP(src=sip, dst=cip)
    return [
        ip_c / TCP(sport=cport, dport=sport, seq=c_isn, flags="S"),
        ip_s / TCP(sport=sport, dport=cport, seq=s_isn, ack=c_isn + 1, flags="SA"),
        ip_c / TCP(sport=cport, dport=sport, seq=c_isn + 1, ack=s_isn + 1, flags="A"),
        ip_c / TCP(sport=cport, dport=sport, seq=c_isn + 1, ack=s_isn + 1,
                   flags="PA") / Raw(load=cdata),
        ip_s / TCP(sport=sport, dport=cport, seq=s_isn + 1,
                   ack=c_isn + 1 + len(cdata), flags="PA") / Raw(load=sdata),
        ip_c / TCP(sport=cport, dport=sport, seq=c_isn + 1 + len(cdata),
                   ack=s_isn + 1 + len(sdata), flags="A"),
    ]


def main():
    pkts = []
    # PADDED split continuation
    pkts += build_connection("10.0.0.1", "10.0.0.2", 55001, 443,
                             padlen=20, priority=b"",
                             c_isn=1000, s_isn=5000,
                             marker_value=b"splitpad-c1")
    # PADDED split continuation response + PADDED + PRIORITY request
    pkts += build_connection("10.0.0.1", "10.0.0.2", 55002, 444,
                             padlen=15, priority=b"",
                             c_isn=2000, s_isn=6000,
                             marker_value=b"splitpad-c2",
                             req_flags=0x2D,  # PADDED|PRIORITY|END_HEADERS|END_STREAM
                             req_prio=b"\x00\x00\x00\x00\x08",
                             req_padlen=5)
    # explicit monotonic timestamps (1 ms apart)
    t = 1700000000.0
    for p in pkts:
        p.time = t
        t += 0.001
    wrpcap("input.pcap", pkts)
    print(f"wrote input.pcap ({len(pkts)} packets)")


if __name__ == "__main__":
    main()
