#!/usr/bin/env python3
"""
Craft the HTTP firewall sweep-bound test pcap.

TCP between 10.0.2.5 (client) and 172.16.0.10:80 (server), two complete
pipelined requests and the (line-only) response to the first one:

  P3 client->server  R1 - completes tx1.
  P4 client->server  R2 - completes tx2; tx1 is now a non-last tx.
  P5 server->client  "HTTP/1.1 200 OK\r\n" - tx1's response line; its
                     progress is response_line, below the tx's end
                     state. The started-state rule (sid 1641) matches
                     mid-walk (hook 0 < progress 1) with no verdict,
                     and there is no next fw rule, so the default
                     policy sweep runs over the states the packet
                     walked over: bounded at tx_progress (state 1, an
                     accept that is non-decisive for a non-last tx) on
                     this branch, and up to tx_end_state on the base
                     release - where it reaches the response-body
                     drop:flow policy (state 3) and drops P5.
                     This is the discriminating packet. tx1 being
                     non-last is load-bearing: it holds because a
                     later pipelined request (tx2) is still open at
                     this point, and it is what keeps the swept
                     accepts non-decisive on the base too.
  P6 client->server  FIN.

Run this script from its own test directory: the pcap is written to
input.pcap.
"""

import socket
import struct

DST = "input.pcap"

CLIENT_IP = "10.0.2.5"
SERVER_IP = "172.16.0.10"
CLIENT_PORT = 4444
SERVER_PORT = 80

MAC_C = bytes.fromhex("aabbccddee01")
MAC_S = bytes.fromhex("aabbccddee02")

C_SEQ = 1000
S_SEQ = 5000

R1 = b"GET /one HTTP/1.1\r\nHost: a\r\n\r\n"
R2 = b"GET /two HTTP/1.1\r\nHost: a\r\n\r\n"
RESP_LINE = b"HTTP/1.1 200 OK\r\n"


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


pkts = [
    (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ, 0, 0x002, b""),
    (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ, C_SEQ + 1, 0x012, b""),
    (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1, S_SEQ + 1, 0x010, R1),
    (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
     C_SEQ + 1 + len(R1), S_SEQ + 1, 0x010, R2),
    (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
     S_SEQ + 1, C_SEQ + 1 + len(R1) + len(R2), 0x010, RESP_LINE),
    (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
     C_SEQ + 1 + len(R1) + len(R2), S_SEQ + 1 + len(RESP_LINE), 0x011, b""),
]

out = []
for src, dst, sport, dport, seq, ack, flags, payload in pkts:
    t = tcp(sport, dport, seq, ack, flags, payload, src, dst)
    out.append((src, dst, t))

with open(DST, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for src, dst, t in out:
        ip = ip4(src, dst, t)
        mac_d = MAC_C if src == SERVER_IP else MAC_S
        mac_s = MAC_S if src == SERVER_IP else MAC_C
        eth = struct.pack("!6s6sH", mac_d, mac_s, 0x0800)
        p = eth + ip
        f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
        f.write(p)

print("wrote %s: %d packets" % (DST, len(out)))
