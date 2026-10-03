#!/usr/bin/env python3
"""
Craft the TLS non-hello first record pcap.

TCP 3-way handshake between 10.0.2.5 (client) and 172.16.0.10:443
(server), then the first TLS records on both tracks are alerts - no
ClientHello is ever sent:

  P4 client->server  TLS alert (level fatal, description 40
                     handshake_failure)
  P6 server->client  TLS alert (level fatal, description 40
                     handshake_failure)

The parser only enters the hello phases on an actual hello record, so
both tracks must stay in their started states.

Run this script from its own test directory: the pcap is written to
input.pcap.
"""

import socket
import struct

DST = "input.pcap"

CLIENT_IP = "10.0.2.5"
SERVER_IP = "172.16.0.10"
CLIENT_PORT = 4444
SERVER_PORT = 443

MAC_C = bytes.fromhex("aabbccddee01")
MAC_S = bytes.fromhex("aabbccddee02")

C_SEQ = 1000
S_SEQ = 5000

TLS_ALERT = b"\x15\x03\x03\x00\x02\x01\x28"  # alert, fatal (TLS 1.2 numbering), handshake_failure


def csum16(buf):
    if len(buf) % 2:
        buf += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(buf) // 2), buf))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ip_pkt(src, dst, payload, ip_id, mac_s, mac_d):
    l4 = socket.IPPROTO_TCP
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ip_id, 0, 64, l4,
                      0, socket.inet_aton(src), socket.inet_aton(dst))
    ck = csum16(hdr)
    hdr = hdr[:10] + struct.pack(">H", ck) + hdr[12:]
    return mac_d + mac_s + b"\x08\x00" + hdr + payload


def tcp_pkt(src, dst, seq, ack, flags, payload, tcp_id):
    dataoff = 5 << 4
    hdr = struct.pack(">HHII BBH HH", src, dst, seq, ack, dataoff, flags,
                      65535, 0, 0)
    hdr = hdr[:16] + struct.pack(">H", csum16(hdr + payload)) + hdr[18:]
    return hdr + payload


def main():
    pkts = []
    ip_id = 1

    def send(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
        nonlocal ip_id
        pkts.append(ip_pkt(src_ip, dst_ip,
                           tcp_pkt(src_port, dst_port, seq, ack, flags,
                                   payload, ip_id), ip_id,
                           MAC_C if src_ip == CLIENT_IP else MAC_S,
                           MAC_S if src_ip == CLIENT_IP else MAC_C))
        ip_id += 1

    c = (CLIENT_IP, CLIENT_PORT)
    s = (SERVER_IP, SERVER_PORT)

    send(c[0], s[0], c[1], s[1], C_SEQ, 0, 0x02, b"")            # P1 SYN
    send(s[0], c[0], s[1], c[1], S_SEQ, C_SEQ + 1, 0x12, b"")    # P2 SYN-ACK
    send(c[0], s[0], c[1], s[1], C_SEQ + 1, S_SEQ + 1, 0x10, b"")  # P3 ACK
    send(c[0], s[0], c[1], s[1], C_SEQ + 1, S_SEQ + 1, 0x18, TLS_ALERT)  # P4 client alert
    send(s[0], c[0], s[1], c[1], S_SEQ + 1, C_SEQ + 1 + len(TLS_ALERT), 0x10, b"")  # P5 ACK
    send(s[0], c[0], s[1], c[1], S_SEQ + 1, C_SEQ + 1 + len(TLS_ALERT), 0x18, TLS_ALERT)  # P6 server alert
    send(c[0], s[0], c[1], s[1], C_SEQ + 1 + len(TLS_ALERT), S_SEQ + 1 + len(TLS_ALERT),
         0x10, b"")                              # P7 ACK

    with open(DST, "wb") as f:
        # classic pcap, little-endian
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            ts = 0
            f.write(struct.pack("<IIII", ts, ts, len(p), len(p)))
            f.write(p)
    print("wrote %s with %d packets" % (DST, len(pkts)))


if __name__ == "__main__":
    main()
