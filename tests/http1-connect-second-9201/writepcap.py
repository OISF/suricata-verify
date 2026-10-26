#!/usr/bin/env python3
"""Build input.pcap for the CONNECT tunnel-bypass suricata-verify test.

Six TCP sessions to port 80, checksums filled in. Replay accepts -k none.
The byte sequences match the live case.
"""
from __future__ import annotations

import struct
from pathlib import Path


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def req(method: str, target: str, close: bool = False, host: str = "origin.example") -> bytes:
    conn = "close" if close else "keep-alive"
    return (
        f"{method} {target} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: {conn}\r\n"
        f"\r\n"
    ).encode()


def http_ok(close: bool) -> bytes:
    token = b"close" if close else b"keep-alive"
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 2\r\n"
        b"Connection: " + token + b"\r\n"
        b"\r\n"
        b"OK"
    )


CONNECT_OK = b"HTTP/1.1 200 Connection Established\r\n\r\n"


class Flow:
    def __init__(self, sport: int, base_us: int) -> None:
        self.sport = sport
        self.cseq = 1000
        self.sseq = 8000
        self.us = base_us
        self.pkts: list[tuple[int, bytes]] = []
        self.client = (0x0A010101, sport)
        self.server = (0x0A010102, 80)

    def _ip_tcp(self, src: tuple[int, int], dst: tuple[int, int], seq: int, ack: int, flags: int, payload: bytes) -> bytes:
        src_ip, sport = src
        dst_ip, dport = dst
        tcp_len = 20 + len(payload)
        data_off = 5 << 4
        tcp_wo = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, data_off, flags, 65535, 0, 0) + payload
        pseudo = struct.pack("!IIBBH", src_ip, dst_ip, 0, 6, tcp_len)
        tcp_sum = checksum(pseudo + tcp_wo)
        tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, data_off, flags, 65535, tcp_sum, 0) + payload
        total = 20 + len(tcp)
        ip_wo = struct.pack("!BBHHHBBHII", 0x45, 0, total, self.sport, 0, 64, 6, 0, src_ip, dst_ip)
        ip_sum = checksum(ip_wo)
        ip = struct.pack("!BBHHHBBHII", 0x45, 0, total, self.sport, 0, 64, 6, ip_sum, src_ip, dst_ip)
        eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
        return eth + ip + tcp

    def _add(self, raw: bytes) -> None:
        self.pkts.append((self.us, raw))
        self.us += 50000

    def handshake(self) -> None:
        syn = 0x02
        ack = 0x10
        self._add(self._ip_tcp(self.client, self.server, self.cseq, 0, syn, b""))
        self._add(self._ip_tcp(self.server, self.client, self.sseq, self.cseq + 1, syn | ack, b""))
        self.cseq += 1
        self.sseq += 1
        self._add(self._ip_tcp(self.client, self.server, self.cseq, self.sseq, ack, b""))

    def c2s(self, payload: bytes) -> None:
        flags = 0x18  # PSH+ACK
        self._add(self._ip_tcp(self.client, self.server, self.cseq, self.sseq, flags, payload))
        self.cseq += len(payload)
        self._add(self._ip_tcp(self.server, self.client, self.sseq, self.cseq, 0x10, b""))

    def s2c(self, payload: bytes) -> None:
        flags = 0x18
        self._add(self._ip_tcp(self.server, self.client, self.sseq, self.cseq, flags, payload))
        self.sseq += len(payload)
        self._add(self._ip_tcp(self.client, self.server, self.cseq, self.sseq, 0x10, b""))

    def close(self) -> None:
        fin = 0x11  # FIN+ACK
        self._add(self._ip_tcp(self.client, self.server, self.cseq, self.sseq, fin, b""))
        self.cseq += 1
        self._add(self._ip_tcp(self.server, self.client, self.sseq, self.cseq, fin, b""))
        self.sseq += 1
        self._add(self._ip_tcp(self.client, self.server, self.cseq, self.sseq, 0x10, b""))


def exchange(flow: Flow, request: bytes, response: bytes) -> None:
    flow.c2s(request)
    flow.s2c(response)


def build() -> list[tuple[int, bytes]]:
    packets: list[tuple[int, bytes]] = []

    ctrl = Flow(41001, 0)
    ctrl.handshake()
    exchange(ctrl, req("GET", "/warmup-ctrl-9f3a"), http_ok(False))
    exchange(ctrl, req("CONNECT", "example.com:443", host="example.com:443"), CONNECT_OK)
    exchange(ctrl, req("GET", "/ctrl-get-marker-9f3a", close=True), http_ok(True))
    ctrl.close()
    packets += ctrl.pkts

    empty = Flow(41002, 2_000_000)
    empty.handshake()
    exchange(empty, req("GET", "/warmup-atk-empty-9f3a"), http_ok(False))
    exchange(empty, req("CONNECT", "example.com:443", host="example.com:443"), CONNECT_OK)
    hidden = req("GET", "/atk-empty-marker-9f3a", close=True)
    exchange(empty, b"\r\n" + hidden, http_ok(True))
    empty.close()
    packets += empty.pkts

    bind = Flow(41003, 4_000_000)
    bind.handshake()
    exchange(bind, req("GET", "/warmup-atk-bind-9f3a"), http_ok(False))
    exchange(bind, req("CONNECT", "example.com:443", host="example.com:443"), CONNECT_OK)
    blob = req("BIND", "example.com:443", host="example.com:443") + req("GET", "/atk-bind-marker-9f3a", close=True)
    bind.c2s(blob)
    bind.s2c(http_ok(False))
    bind.s2c(http_ok(True))
    bind.close()
    packets += bind.pkts

    search = Flow(41004, 6_000_000)
    search.handshake()
    exchange(search, req("GET", "/warmup-atk-search-9f3a"), http_ok(False))
    exchange(search, req("CONNECT", "example.com:443", host="example.com:443"), CONNECT_OK)
    blob = req("SEARCH", "/probe") + req("GET", "/atk-search-marker-9f3a", close=True)
    search.c2s(blob)
    search.s2c(http_ok(False))
    search.s2c(http_ok(True))
    search.close()
    packets += search.pkts

    lone_get = Flow(41005, 8_000_000)
    lone_get.handshake()
    exchange(lone_get, req("CONNECT", "example.com:443", host="example.com:443"), CONNECT_OK)
    exchange(lone_get, req("GET", "/lone-get-marker-9f3a", close=True), http_ok(True))
    lone_get.close()
    packets += lone_get.pkts

    lone_bind = Flow(41006, 10_000_000)
    lone_bind.handshake()
    exchange(lone_bind, req("CONNECT", "example.com:443", host="example.com:443"), CONNECT_OK)
    exchange(lone_bind, req("BIND", "example.com:443", host="example.com:443"), http_ok(False))
    exchange(lone_bind, req("GET", "/lone-bind-marker-9f3a", close=True), http_ok(True))
    lone_bind.close()
    packets += lone_bind.pkts

    packets.sort(key=lambda item: item[0])
    return packets


def main() -> None:
    packets = build()
    global_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = bytearray()
    for ts, pkt in packets:
        sec, usec = divmod(ts, 1_000_000)
        body += struct.pack("<IIII", sec, usec, len(pkt), len(pkt))
        body += pkt
    out = Path(__file__).resolve().parent / "input.pcap"
    out.write_bytes(global_hdr + body)
    print(f"wrote {out.name} packets={len(packets)} bytes={out.stat().st_size}")


if __name__ == "__main__":
    main()
