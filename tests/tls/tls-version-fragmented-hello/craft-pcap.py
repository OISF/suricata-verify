#!/usr/bin/env python3
"""
Craft a pcap whose ClientHello is split across two TLS records so that the
record layer version differs from the hello version, and the hello header
alone arrives in the first record:

  P1-P3  TCP 3-way handshake (10.0.2.5:4444 -> 172.16.0.10:443)
  P4     client->server  TLS record #1: content type 22 (handshake),
                         record version 0x0301 (TLS 1.0), length 4,
                         body = the 4 byte ClientHello handshake header
                         (type 1, length = full hello body). The record
                         layer version is therefore the only version known
                         when the parser enters the client_hello phase.
  P6     client->server  TLS record #2: content type 22,
                         record version 0x0301, length 43, body = the
                         ClientHello body, whose first two bytes are the
                         hello version 0x0303 (TLS 1.2).

The parser buffers the fragmented handshake message: the phase is entered
on the record #1 handshake header, while the hello version is only decoded
when record #2 completes the message. A tls.version / ssl_version rule must
be able to match the hello version on the completed hello.

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

# ClientHello body: version 0x0303 (TLS 1.2), random, empty session id,
# one cipher suite, null compression, no extensions.
HELLO_BODY = (struct.pack(">H", 0x0303) + b"\x11" * 32 + b"\x00" +
              struct.pack(">H", 2) + b"\x00\x2f" + b"\x01\x00" +
              struct.pack(">H", 0))
assert len(HELLO_BODY) == 43

# record #1: only the ClientHello handshake header
HS_HEADER = struct.pack(">B", 1) + struct.pack(">I", len(HELLO_BODY))[1:]


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

    rec1 = tls_record(22, 0x0301, HS_HEADER)
    rec2 = tls_record(22, 0x0301, HELLO_BODY)
    # a follow up toserver record so the version keyword is evaluated on a
    # packet after the hello completes (see the test.yaml note)
    rec3 = tls_record(23, 0x0303, b"\xaa" * 8)

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
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
         C_SEQ + 1 + len(rec1) + len(rec2), S_SEQ + 1, 0x18, rec3)
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ + 1,
         C_SEQ + 1 + len(rec1) + len(rec2) + len(rec3), 0x10, b"")

    with open(DST, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    print("wrote %s with %d packets" % (DST, len(pkts)))


if __name__ == "__main__":
    main()
