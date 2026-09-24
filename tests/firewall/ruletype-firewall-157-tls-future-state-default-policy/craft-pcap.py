#!/usr/bin/env python3
"""
Craft the future-state-default-policy test pcap.

A minimal TLS1.2 session: 3-way handshake, one complete ClientHello
(the state advancing packet), one ServerHello; the capture ends there.
The ClientHello completes into the client_cert state; the client never
sends a ChangeCipherSpec or app data, so client_data is a future state
on every packet of this capture.

The point: the default-policy sweep of the walked-over states must
stop at the current progress. A drop:flow config policy on client_data
(never reached here) must not decide the ClientHello packet: pre clamp
the match-path sweep ran up to the completion state and dropped the
session on its first advancing packet.

Run from its own test directory; writes input.pcap.
"""

import socket
import struct

CLIENT_IP = "10.0.2.5"
SERVER_IP = "172.16.0.10"
CLIENT_PORT = 4444
SERVER_PORT = 443
MAC_C = b"\x02\x42\xac\x10\x00\x05"
MAC_S = b"\x02\x42\xac\x10\x00\x0a"
C_SEQ = 1000
S_SEQ = 5000


def csum16(buf):
    if len(buf) % 2:
        buf += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(buf) // 2), buf))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ip_pkt(src, dst, payload, ip_id, mac_s, mac_d):
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ip_id, 0, 64, 6,
                      0, socket.inet_aton(src), socket.inet_aton(dst))
    ck = csum16(hdr)
    hdr = hdr[:10] + struct.pack(">H", ck) + hdr[12:]
    return mac_d + mac_s + b"\x08\x00" + hdr + payload


def tcp_pkt(src, dst, seq, ack, flags, payload):
    hdr = struct.pack(">HHIIBBHHH", src, dst, seq, ack, 5 << 4, flags, 65535, 0, 0)
    hdr = hdr[:16] + struct.pack(">H", csum16(hdr + payload)) + hdr[18:]
    return hdr + payload


def client_hello():
    random = bytes(range(32))
    ciphers = bytes.fromhex("c02fc02cc030009c009d")
    sni = b"example.com"
    sni_ext = b"\x00\x00" + struct.pack(">H", 16) + struct.pack(">H", 14) + \
        b"\x00" + struct.pack(">H", len(sni)) + sni
    sv_ext = b"\x00\x2b" + struct.pack(">H", 5) + b"\x00\x03\x03\x04\x03\x03"
    exts = sni_ext + sv_ext
    body = b"\x03\x03" + random + b"\x00" + struct.pack(">H", len(ciphers)) + ciphers + \
        b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    return b"\x16\x03\x03" + struct.pack(">H", len(body) + 4) + \
        b"\x01" + struct.pack(">I", len(body))[1:] + body


def server_hello():
    body = b"\x03\x03" + bytes(range(32, 64)) + bytes([32]) + bytes(range(64, 96)) + \
        b"\xc0\x2f" + b"\x00"
    return b"\x16\x03\x03" + struct.pack(">H", len(body) + 4) + \
        b"\x02" + struct.pack(">I", len(body))[1:] + body


def main():
    pkts = []
    ip_id = 1

    def send(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
        nonlocal ip_id
        pkts.append(ip_pkt(src_ip, dst_ip,
                           tcp_pkt(sport, dport, seq, ack, flags, payload), ip_id,
                           MAC_C if src_ip == CLIENT_IP else MAC_S,
                           MAC_S if src_ip == CLIENT_IP else MAC_C))
        ip_id += 1

    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ, 0, 0x02)
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ, C_SEQ + 1, 0x12)
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1, S_SEQ + 1, 0x10)
    ch = client_hello()
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1, S_SEQ + 1, 0x18, ch)
    sh = server_hello()
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ + 1, C_SEQ + 1 + len(ch),
         0x18, sh)

    with open("input.pcap", "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    print("wrote input.pcap: %d packets, CH %d bytes" % (len(pkts), len(ch)))


if __name__ == "__main__":
    main()
