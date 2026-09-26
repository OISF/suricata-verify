#!/usr/bin/env python3
"""
Craft the SSLv2 state pin firewall test pcap.

TCP handshake between 10.0.2.5 (client) and 172.16.0.10:443 (server),
then a minimal SSLv2 session (record header 0x80|len_hi, len_lo,
msg_type; the length counts the msg_type byte plus the body):

  P1 client->server  TCP SYN
  P2 server->client  TCP SYN/ACK
  P3 client->server  SSLv2 client hello: the v3 state machine moves
                     the client track to client_hello
  P4 server->client  SSLv2 server hello: the v3 state machine moves
                     the server track to server_hello
  P5 client->server  SSLv2 client certificate (type 0xFE): the v3
                     state machine moves the client track to
                     client_cert; the v2 certificate payload itself
                     is not extracted, and the server track is not
                     touched (it stays in server_hello)
  P6 client->server  TCP FIN

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

CHALLENGE = bytes(range(16))
CIPHER_SPECS = b"\x01\x00\x02\x00\x03\x00\x04\x00"  # 4 spec codes
CERT_PAYLOAD = bytes([0xAA] * 16)  # not extracted, content irrelevant


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


# The SSLv2 record header is [0x80 | len >> 8, len & 0xff, msg_type] and
# the length counts the msg_type byte plus the body (suricata's parser
# model: the record is complete after length + 2 header bytes).
def v2_record(msg_type, body):
    return b"\x80" + struct.pack("!B", len(body) + 1) + bytes([msg_type]) + body


def v2_client_hello():
    # body: client_version (2) + cipher_spec_length (2) + session_id_length
    # (2), then the remaining fields (not validated by the parser)
    body = struct.pack("!HHH", 0x0200, len(CIPHER_SPECS), 0)
    body += struct.pack("!H", len(CIPHER_SPECS))
    body += CIPHER_SPECS
    body += struct.pack("!H", len(CHALLENGE))
    body += CHALLENGE
    return v2_record(0x01, body)


def v2_server_hello():
    body = struct.pack("!HH", 0x0200, 0x0100)  # version, negotiated cipher
    body += struct.pack("!H", 0)  # session id len
    body += struct.pack("!H", 0)  # challenge len
    return v2_record(0x04, body)


def v2_client_certificate():
    body = struct.pack("!HH", 0x0200, len(CERT_PAYLOAD))
    body += CERT_PAYLOAD
    return v2_record(0x08, body)


v2ch = v2_client_hello()
v2sh = v2_server_hello()
v2cc = v2_client_certificate()

pkts = [
    (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ, 0, 0x002, b"", C_SEQ),
    (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ, C_SEQ + 1, 0x012, b"", S_SEQ),
    (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1, S_SEQ + 1, 0x010, v2ch, C_SEQ + 1 + len(v2ch)),
    (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ + 1, C_SEQ + 1, 0x010, v2sh, S_SEQ + 1 + len(v2sh)),
    (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1 + len(v2ch), S_SEQ + 1, 0x010, v2cc, C_SEQ + 1 + len(v2ch) + len(v2cc)),
    (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1 + len(v2ch) + len(v2cc), S_SEQ + 1, 0x011, b"", C_SEQ + 2 + len(v2ch) + len(v2cc)),
]

out = []
for src, dst, sport, dport, seq, ack, flags, payload, _nxt in pkts:
    t = tcp(sport, dport, seq, ack, flags, payload, src, dst)
    out.append((src, dst, t))

import struct as st
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
