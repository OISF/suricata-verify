#!/usr/bin/env python3
"""
Craft a pcap with a record-fragmented TLS 1.3 ClientHello.

The ClientHello negotiates TLS 1.3 through the supported_versions extension
(0x0304); its legacy/record layer version is 0x0303 (TLS 1.2). The handshake
message is split across two TLS records:

  P4 client->server  record #1: content type 22, record version 0x0303,
                     body = ClientHello handshake header + the first 40 body
                     bytes. The client_hello phase is entered here, but the
                     only version visible is the record layer 0x0303 (TLS 1.2).
  P6 client->server  record #2: content type 22, record version 0x0303,
                     body = the last 10 body bytes, containing the
                     supported_versions extension. Completing the message
                     decodes the negotiated version 0x0304 (TLS 1.3).

A tls.version rule hooked early (tls:client_started) must not treat the
pre-1.3 miss as final: the version is only final once the hello, including
supported_versions, decoded.

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

# TLS 1.3 ClientHello body: legacy version 0x0303, one TLS 1.3 cipher suite,
# null compression and a single supported_versions extension (0x0304).
SUPPORTED_VERSIONS = (struct.pack(">HH", 0x002b, 3) + b"\x02" +
                     struct.pack(">H", 0x0304))
HELLO_BODY = (struct.pack(">H", 0x0303) + b"\x11" * 32 + b"\x00" +
              struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" +
              struct.pack(">H", len(SUPPORTED_VERSIONS)) + SUPPORTED_VERSIONS)
HS_HEADER = struct.pack(">B", 1) + struct.pack(">I", len(HELLO_BODY))[1:]

# split so that supported_versions is only in the second record
SPLIT = 40
assert SPLIT < len(HELLO_BODY) - len(SUPPORTED_VERSIONS) + len(SUPPORTED_VERSIONS)
assert len(HELLO_BODY) - SPLIT >= len(SUPPORTED_VERSIONS)


def csum16(buf):
    if len(buf) % 2:
        buf += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(buf) // 2), buf))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ip_pkt(src, dst, payload, ip_id, mac_s, mac_d):
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ip_id, 0, 64,
                      socket.IPPROTO_TCP, 0, socket.inet_aton(src),
                      socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack(">H", csum16(hdr)) + hdr[12:]
    return mac_d + mac_s + b"\x08\x00" + hdr + payload


def tcp_pkt(src, dst, seq, ack, flags, payload):
    hdr = struct.pack(">HHIIBBHHH", src, dst, seq, ack, (5 << 4), flags,
                      65535, 0, 0)
    hdr = hdr[:16] + struct.pack(">H", csum16(hdr + payload)) + hdr[18:]
    return hdr + payload


def tls_record(rtype, version, body):
    return struct.pack(">BHH", rtype, version, len(body)) + body


def main():
    pkts = []
    ip_id = 1

    def send(src_ip, dst_ip, sport, dport, seq, ack, flags, payload):
        nonlocal ip_id
        pkts.append(ip_pkt(src_ip, dst_ip,
                           tcp_pkt(sport, dport, seq, ack, flags, payload),
                           ip_id,
                           MAC_C if src_ip == CLIENT_IP else MAC_S,
                           MAC_S if src_ip == CLIENT_IP else MAC_C))
        ip_id += 1

    rec1 = tls_record(22, 0x0303, HS_HEADER + HELLO_BODY[:SPLIT])
    rec2 = tls_record(22, 0x0303, HELLO_BODY[SPLIT:])

    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ, 0, 0x02, b"")
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ, C_SEQ + 1,
         0x12, b"")
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1, S_SEQ + 1,
         0x10, b"")
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1, S_SEQ + 1,
         0x18, rec1)
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ + 1,
         C_SEQ + 1 + len(rec1), 0x10, b"")
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
         C_SEQ + 1 + len(rec1), S_SEQ + 1, 0x18, rec2)
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ + 1,
         C_SEQ + 1 + len(rec1) + len(rec2), 0x10, b"")

    with open(DST, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    print("wrote %s with %d packets" % (DST, len(pkts)))


if __name__ == "__main__":
    main()
