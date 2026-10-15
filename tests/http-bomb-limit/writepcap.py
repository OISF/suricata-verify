#!/usr/bin/env python3
"""Build input.pcap for the suricata-verify test. Standard library only."""
import gzip
import io
import struct
import socket
from pathlib import Path

# brotli of 1 MiB + 8 KiB zeros, window 256 KiB. Ratio is far above 2048.
# gzip/deflate cannot reach that ratio, so these bodies are what increments bombs.
PLAIN = 1048576 + 8192
BOMB = bytes.fromhex(
    "a3ffff837f02201e0b0472ef0ff4ff7ff04f00c4611180eefd41fc7fe09f0088c30200dd0b00"
)
assert PLAIN / len(BOMB) > 2048
MARKER = b"E2EGZIPMARKER"
GZIP_PLAIN = MARKER + b"\x00" * (64 * 1024 - len(MARKER))
PLAIN_BODY = b"E2EPLAINMARKER\n"
def _gzip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()


GZIP_BODY = _gzip(GZIP_PLAIN)


def http_resp(encoding, body, close=False):
    conn = "close" if close else "keep-alive"
    headers = [
        "HTTP/1.1 200 OK",
        "Content-Type: application/octet-stream",
        f"Content-Length: {len(body)}",
        f"Connection: {conn}",
    ]
    if encoding:
        headers.append(f"Content-Encoding: {encoding}")
    return ("\r\n".join(headers) + "\r\n\r\n").encode() + body


def http_req(path):
    msg = (
        f"GET {path} HTTP/1.1\r\n"
        "Host: bomb.test\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    )
    return msg.encode()


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(payload: bytes) -> bytes:
    return bytes.fromhex("000102030405") + bytes.fromhex("00090a0b0c0d") + b"\x08\x00" + payload


def ipv4(src, dst, payload, ident) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, ident & 0xFFFF, 0, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, ident & 0xFFFF, 0, 64, 6, csum(hdr),
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return hdr + payload


def tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b"") -> bytes:
    off_flags = (5 << 12) | flags
    base = struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags, 65535, 0, 0)
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, 6, len(base) + len(payload),
    )
    chk = csum(pseudo + base + payload)
    base = struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags, 65535, chk, 0)
    return base + payload


SYN, ACK, FIN, PSH = 0x02, 0x10, 0x01, 0x08


class Flow:
    def __init__(self, pkts, client, server, sport, dport):
        self.pkts = pkts
        self.client = client
        self.server = server
        self.sport = sport
        self.dport = dport
        self.cseq = 1000
        self.sseq = 5000
        self.ident = sport

    def _pkt(self, src, dst, sport, dport, seq, ack, flags, payload=b""):
        seg = tcp(src, dst, sport, dport, seq, ack, flags, payload)
        ip = ipv4(src, dst, seg, self.ident)
        self.ident += 1
        self.pkts.append(eth(ip))

    def handshake(self):
        self._pkt(self.client, self.server, self.sport, self.dport, self.cseq, 0, SYN)
        self.cseq += 1
        self._pkt(self.server, self.client, self.dport, self.sport, self.sseq, self.cseq, SYN | ACK)
        self.sseq += 1
        self._pkt(self.client, self.server, self.sport, self.dport, self.cseq, self.sseq, ACK)

    def client_data(self, payload: bytes):
        self._pkt(self.client, self.server, self.sport, self.dport, self.cseq, self.sseq, PSH | ACK, payload)
        self.cseq += len(payload)
        self._pkt(self.server, self.client, self.dport, self.sport, self.sseq, self.cseq, ACK)

    def server_data(self, payload: bytes):
        # split so each segment stays under a typical MTU
        off = 0
        while off < len(payload):
            chunk = payload[off:off + 1200]
            flags = PSH | ACK if off + len(chunk) >= len(payload) else ACK
            self._pkt(self.server, self.client, self.dport, self.sport, self.sseq, self.cseq, flags, chunk)
            self.sseq += len(chunk)
            self._pkt(self.client, self.server, self.sport, self.dport, self.cseq, self.sseq, ACK)
            off += len(chunk)

    def close(self):
        self._pkt(self.client, self.server, self.sport, self.dport, self.cseq, self.sseq, FIN | ACK)
        self.cseq += 1
        self._pkt(self.server, self.client, self.dport, self.sport, self.sseq, self.cseq, FIN | ACK)
        self.sseq += 1
        self._pkt(self.client, self.server, self.sport, self.dport, self.cseq, self.sseq, ACK)


def conversation(flow, prefix, bombs, close_last=True):
    for i in range(1, bombs + 1):
        flow.client_data(http_req(f"/{prefix}/bomb/{i}"))
        flow.server_data(http_resp("br", BOMB))
    flow.client_data(http_req(f"/{prefix}/gzip-marker"))
    flow.server_data(http_resp("gzip", GZIP_BODY))
    flow.client_data(http_req(f"/{prefix}/after-plain"))
    flow.server_data(http_resp(None, PLAIN_BODY, close=close_last))
    flow.close()


def write_pcap(path: Path, frames):
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    out = [gh]
    ts = 0
    for i, frame in enumerate(frames):
        ts_sec = i // 10
        ts_usec = (i % 10) * 100000
        out.append(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
        out.append(frame)
    path.write_bytes(b"".join(out))


def main():
    frames = []
    client, server = "192.0.2.20", "192.0.2.10"
    control = Flow(frames, client, server, 40000, 80)
    control.handshake()
    conversation(control, "c", 2)
    attack = Flow(frames, client, server, 40001, 80)
    attack.handshake()
    conversation(attack, "a", 3)
    write_pcap(Path(__file__).resolve().parent / "input.pcap", frames)
    print(f"bomb_len={len(BOMB)} bomb_plain={PLAIN} ratio={PLAIN/len(BOMB):.1f}")
    print(f"gzip_len={len(GZIP_BODY)} gzip_plain={len(GZIP_PLAIN)}")
    print(f"packets={len(frames)}")


if __name__ == "__main__":
    main()
