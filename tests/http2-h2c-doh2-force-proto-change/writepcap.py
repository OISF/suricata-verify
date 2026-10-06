#!/usr/bin/env python3
"""Build the h2c-upgrade + DoH2 HEADERS pcap that hits the ForceProtocolChange window."""

from __future__ import annotations

import base64
import struct
import sys


def ipv4_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_checksum(src: bytes, dst: bytes, tcp: bytes) -> int:
    return ipv4_checksum(src + dst + struct.pack("!BBH", 0, 6, len(tcp)) + tcp)


def dns_a_query(name: str, txid: int = 0x1234) -> bytes:
    qname = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        qname += bytes([len(raw)]) + raw
    qname += b"\x00"
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack("!HH", 1, 1)


def hpack_int(value: int, prefix_bits: int, prefix_hi: int) -> bytes:
    maxv = (1 << prefix_bits) - 1
    if value < maxv:
        return bytes([prefix_hi | value])
    out = [prefix_hi | maxv]
    value -= maxv
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def hpack_string(s: bytes) -> bytes:
    return hpack_int(len(s), 7, 0) + s


def hpack_lit_noindex(index: int, value: bytes) -> bytes:
    return hpack_int(index, 4, 0x00) + hpack_string(value)


def http2_frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        struct.pack("!I", len(payload))[1:]
        + bytes([ftype, flags])
        + struct.pack("!I", stream_id & 0x7FFFFFFF)
        + payload
    )


def build_http2_doh(path: bytes) -> bytes:
    magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = http2_frame(0x04, 0x00, 0, b"")
    hpack = (
        b"\x82"  # :method GET
        + b"\x87"  # :scheme https
        + hpack_lit_noindex(4, path)  # :path
        + hpack_lit_noindex(19, b"application/dns-message")
    )
    # END_HEADERS | END_STREAM on stream 3 (stream 1 is taken by h2c mimic)
    return magic + settings + http2_frame(0x01, 0x05, 3, hpack)


ETH_CLIENT = bytes.fromhex("001122334455")
ETH_SERVER = bytes.fromhex("00aabbccddee")
IP_CLIENT = bytes.fromhex("c000020a")  # 192.0.2.10
IP_SERVER = bytes.fromhex("c0000214")  # 192.0.2.20
SPORT = 49152
DPORT = 80


def ip_tcp(
    src_ip: bytes,
    dst_ip: bytes,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    ident: int,
) -> bytes:
    tcp_len = 20 + len(payload)
    tcp_wo = struct.pack("!HHIIHHHH", sport, dport, seq, ack, 0x5000 | flags, 0x4000, 0, 0)
    csum = tcp_checksum(src_ip, dst_ip, tcp_wo + payload)
    tcp = (
        struct.pack("!HHIIHHHH", sport, dport, seq, ack, 0x5000 | flags, 0x4000, csum, 0)
        + payload
    )
    ip_wo = struct.pack("!BBHHHBBH", 0x45, 0, 20 + tcp_len, ident, 0, 64, 6, 0) + src_ip + dst_ip
    ip = (
        struct.pack("!BBHHHBBH", 0x45, 0, 20 + tcp_len, ident, 0, 64, 6, ipv4_checksum(ip_wo))
        + src_ip
        + dst_ip
    )
    src_eth = ETH_CLIENT if src_ip == IP_CLIENT else ETH_SERVER
    dst_eth = ETH_SERVER if src_ip == IP_CLIENT else ETH_CLIENT
    return dst_eth + src_eth + struct.pack("!H", 0x0800) + ip + tcp


def pcap_header() -> bytes:
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def pcap_pkt(ts: int, data: bytes) -> bytes:
    return struct.pack("<IIII", ts, 0, len(data), len(data)) + data


def seq_advance(flags: int, payload: bytes) -> int:
    if payload:
        return len(payload)
    if flags & 0x03:  # SYN or FIN
        return 1
    return 0


def build_pcap() -> bytes:
    wire = dns_a_query("example.com")
    b64 = base64.b64encode(wire).rstrip(b"=")
    path = b"/dns-query?dns=" + b64
    h2 = build_http2_doh(path)

    req = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Connection: Upgrade, HTTP2-Settings\r\n"
        b"Upgrade: h2c\r\n"
        b"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
        b"\r\n"
    )
    resp = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Connection: Upgrade\r\n"
        b"Upgrade: h2c\r\n"
        b"\r\n"
    )

    cseq, sseq = 1000, 2000
    ident = 1
    pkts: list[bytes] = []

    def c2s(flags: int, payload: bytes) -> None:
        nonlocal cseq, ident
        pkts.append(ip_tcp(IP_CLIENT, IP_SERVER, SPORT, DPORT, cseq, sseq, flags, payload, ident))
        cseq += seq_advance(flags, payload)
        ident += 1

    def s2c(flags: int, payload: bytes) -> None:
        nonlocal sseq, ident
        pkts.append(ip_tcp(IP_SERVER, IP_CLIENT, DPORT, SPORT, sseq, cseq, flags, payload, ident))
        sseq += seq_advance(flags, payload)
        ident += 1

    c2s(0x02, b"")
    s2c(0x12, b"")
    c2s(0x10, b"")
    c2s(0x18, req)
    s2c(0x10, b"")
    s2c(0x18, resp)
    c2s(0x10, b"")
    c2s(0x18, h2)
    s2c(0x10, b"")
    c2s(0x11, b"")
    s2c(0x11, b"")

    blob = pcap_header()
    start = 1_700_000_000
    for i, pkt in enumerate(pkts):
        blob += pcap_pkt(start + i, pkt)
    return blob


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
    data = build_pcap()
    with open(out, "wb") as fh:
        fh.write(data)
    print("wrote %s bytes=%d" % (out, len(data)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
