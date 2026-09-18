#!/usr/bin/env python3
"""
Craft the TLS malformed-hello/certificate firewall test pcap.

TCP 3-way handshake between 10.0.2.5 (client) and 172.16.0.10:443
(server), then:

  P4 client->server  TLS handshake record: a ClientHello whose message
                     length is 6 - the version (2 bytes) parses but the
                     32-byte random field is truncated, so the message
                     fails to decode
  P5 server->client  TLS handshake record: a fully valid ServerHello
  P6 server->client  TLS handshake record: a Certificate message with a
                     10-byte garbage "certificate" (not an ASN.1
                     SEQUENCE), so the certificate fails to decode
  P7 client->server  TCP FIN

P4 and P6 are deliberately malformed (tshark dissects the outer TLS
record and flags the inner message); the point is that a decode
failure must not enter the phase state: the phase data (SNI,
certificates) does not exist for a message that failed to decode.
A decode failure suppresses the phase advance of its own message
only: the message bytes are consumed, the flow is not dropped, and
the next message that decodes cleanly still advances.

The phase state must stay put on these failures: client_hello is never
entered (the track stays in client_started), server_hello is entered
by the valid P5 ServerHello, and server_cert is never entered (the
track stays in server_hello).

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
    hdr = struct.pack(">HHII BBH HH", src, dst, seq, ack, 5 << 4, flags, 65535, 0, 0)
    hdr = hdr[:16] + struct.pack(">H", csum16(hdr + payload)) + hdr[18:]
    return hdr + payload


def rec(body):
    return b"\x16\x03\x03" + struct.pack(">H", len(body)) + body


def client_hello_truncated():
    # handshake type 1 (ClientHello), message length 6: version (2)
    # plus 4 of the 32 random bytes - the random field does not fit
    body = b"\x01" + struct.pack(">I", 6)[1:] + b"\x03\x03" + b"\x01\x02\x03\x04"
    return rec(body)


def server_hello():
    # RFC ServerHello: version, random, session_id_len + session_id,
    # then the SELECTED cipher suite (2 bytes, no length field) and the
    # compression method (1 byte, no count) - the parser expects exactly
    # this layout
    random = bytes(range(32))
    session_id = b"\xaa"
    selected_suite = b"\x13\x01"
    hs_body = (b"\x03\x03" + random +
               b"\x01" + session_id +
               selected_suite +
               b"\x00")
    return rec(b"\x02" + struct.pack(">I", len(hs_body))[1:] + hs_body)


def certificate_garbage():
    der = b"\x41" * 10  # not an ASN.1 SEQUENCE
    # certificate list: total_length, then per cert: length + data (no
    # count byte - RFC 5246 / parser layout)
    chain = struct.pack(">I", len(der))[1:] + der
    body = b"\x0b" + struct.pack(">I", 3 + len(chain))[1:] + \
        struct.pack(">I", len(chain))[1:] + chain
    return rec(body)


def main():
    pkts = []
    ip_id = 1

    def send(src_ip, dst_ip, sport, dport, seq, ack, flags, payload):
        nonlocal ip_id
        pkts.append(ip_pkt(src_ip, dst_ip,
                           tcp_pkt(sport, dport, seq, ack, flags, payload), ip_id,
                           MAC_C if src_ip == CLIENT_IP else MAC_S,
                           MAC_S if src_ip == CLIENT_IP else MAC_C))
        ip_id += 1

    # 3-way handshake
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ, 0, 0x02, b"")
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ, C_SEQ + 1, 0x12, b"")
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1, S_SEQ + 1, 0x01, b"")

    ch = client_hello_truncated()
    sh = server_hello()
    cert = certificate_garbage()

    c_seq = C_SEQ + 1
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, S_SEQ + 1, 0x18, ch)
    c_seq += len(ch)
    s_seq = S_SEQ + 1
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, 0x18, sh)
    s_seq += len(sh)
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, 0x18, cert)
    s_seq += len(cert)
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, 0x01, b"")

    with open(DST, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    print("wrote %s: %d packets (truncated CH %d B, SH %d B, garbage cert %d B)"
          % (DST, len(pkts), len(ch), len(sh), len(cert)))


if __name__ == "__main__":
    main()
