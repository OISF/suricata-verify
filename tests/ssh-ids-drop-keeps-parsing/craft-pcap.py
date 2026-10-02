#!/usr/bin/env python3
"""
Craft the IDS drop-keeps-parsing test pcap.

TCP handshake between 10.0.2.5 (client) and 172.16.0.10:22 (server), then:

  P1 client->server  TCP SYN
  P2 server->client  TCP SYN/ACK
  P3 client->server  TCP ACK
  P4 client->server  client banner (parsed early)
  P5 server->client  TCP ACK
  P6 client->server  small client data packet: releases the banner for
                     inspection, so the drop rule fires while only the
                     client banner is known
  P7 server->client  server banner
  P8 client->server  TCP ACK
  P9 client->server  TCP FIN/ACK

The drop rule matches the client banner content: in IDS mode parsing
continues, so the ssh record must wait for both banners.

Run this script from its own test directory: the pcap is written to
input.pcap.
"""

import socket
import struct

DST = "input.pcap"

CLIENT_IP = "10.0.2.5"
SERVER_IP = "172.16.0.10"
CLIENT_PORT = 4444
SERVER_PORT = 22

MAC_C = bytes.fromhex("aabbccddee01")
MAC_S = bytes.fromhex("aabbccddee02")

C_SEQ = 1000
S_SEQ = 5000

CLIENT_BANNER = b"SSH-2.0-OpenSSH_for_Windows_7.7\r\n"
SERVER_BANNER = b"SSH-2.0-OpenSSH_7.4\r\n"
CLIENT_DATA = b"\x00\x00\x00\x14\x05\x14" + bytes(range(16))


def csum16(buf):
    if len(buf) % 2:
        buf += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(buf) // 2), buf))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ip4(src, dst, payload):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", csum16(hdr)) + hdr[12:]
    return hdr + payload


def tcp(src, dst, seq, ack, flags, payload, srcip, dstip):
    hdr = struct.pack("!HHLLBBHHH", src, dst, seq, ack, 5 << 4, flags,
                      65535, 0, 0)
    total = hdr + payload
    csum = csum16(ip4(srcip, dstip, total))
    hdr = hdr[:16] + struct.pack("!H", csum) + hdr[18:]
    return hdr + payload


c = CLIENT_IP
s = SERVER_IP
cp, sp = CLIENT_PORT, SERVER_PORT
cs, ss = C_SEQ, S_SEQ

pkts = [
    (c, s, cp, sp, cs, 0, 0x002, b""),
    (s, c, sp, cp, ss, cs + 1, 0x012, b""),
    (c, s, cp, sp, cs + 1, ss + 1, 0x010, b""),
    (c, s, cp, sp, cs + 1, ss + 1, 0x018, CLIENT_BANNER),
    (s, c, sp, cp, ss + 1, cs + 1 + len(CLIENT_BANNER), 0x010, b""),
    (c, s, cp, sp, cs + 1 + len(CLIENT_BANNER), ss + 1, 0x018, CLIENT_DATA),
    (s, c, sp, cp, ss + 1, cs + 1 + len(CLIENT_BANNER) + len(CLIENT_DATA), 0x018, SERVER_BANNER),
    (c, s, cp, sp, cs + 1 + len(CLIENT_BANNER) + len(CLIENT_DATA), ss + 1 + len(SERVER_BANNER), 0x010, b""),
    (c, s, cp, sp, cs + 1 + len(CLIENT_BANNER) + len(CLIENT_DATA), ss + 1 + len(SERVER_BANNER), 0x011, b""),
]

with open(DST, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for src, dst, sport, dport, seq, ack, flags, payload in pkts:
        t = tcp(sport, dport, seq, ack, flags, payload, src, dst)
        ip = ip4(src, dst, t)
        mac_d = MAC_C if src == SERVER_IP else MAC_S
        mac_s = MAC_S if src == SERVER_IP else MAC_C
        eth = struct.pack("!6s6sH", mac_d, mac_s, 0x0800)
        pkt = eth + ip
        f.write(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)))
        f.write(pkt)
print("wrote %s: %d packets" % (DST, len(pkts)))
