#!/usr/bin/env python3
"""
Craft the segmented TLS certificate chain length test pcap.

Two client->server sessions (10.0.2.5 -> 172.16.0.10) with a short
handshake: ClientHello, ServerHello, Certificate, ServerHelloDone.

  port 8443  a two-certificate chain split over three records: after
             the ServerHello the track sits in the server certificate
             phase with no chain parsed yet, and the certificate
             message itself is still in flight for two more packets
             (one certificate fully decoded on the second of them)
  port 8444  a single-certificate chain in one record

The rule alerts while the chain is shorter than two certificates.
The chain length may only be evaluated once the certificate message
has decoded fully: on port 8443 it never is shorter than two at that
point (no alert), on port 8444 it is, once, on the packet that
completes the certificate message (pkt 15).

Certificate bodies are the committed self-signed certificate (via the
ruletype-firewall-153 test directory), used twice for the two-certificate
chain.

Run this script from its own test directory: the pcap is written to
input.pcap.
"""

import os
import socket
import struct

DST = "input.pcap"

CLIENT_IP = "10.0.2.5"
SERVER_IP = "172.16.0.10"

DER = os.path.join("ruletype-firewall-153-tls-malformed-cert", "client_cert.der")

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


def ip_pkt(src, dst, payload, ip_id):
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ip_id, 0, 64, 6,
                      0, socket.inet_aton(src), socket.inet_aton(dst))
    ck = csum16(hdr)
    hdr = hdr[:10] + struct.pack(">H", ck) + hdr[12:]
    s = MAC_S if src == CLIENT_IP else MAC_C
    d = MAC_C if src == CLIENT_IP else MAC_S
    return d + s + b"\x08\x00" + hdr + payload


def tcp_pkt(sport, dport, seq, ack, flags, payload):
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    hdr = hdr[:16] + struct.pack(">H", csum16(hdr + payload)) + hdr[18:]
    return hdr + payload


def hs(t, body):
    return bytes([t]) + struct.pack(">I", len(body))[1:] + body


def rec(ct, payload):
    return bytes([ct]) + b"\x03\x03" + struct.pack(">H", len(payload)) + payload


def client_hello():
    ciphers = b"\xc0\x2f"
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00" +
            struct.pack(">H", len(ciphers)) + ciphers + b"\x01\x00" +
            struct.pack(">H", 0))
    return hs(1, body)


def server_hello():
    return hs(2, b"\x03\x03" + bytes(range(32, 64)) + bytes([32]) +
             bytes(range(96, 128)) + b"\xc0\x2f" + b"\x00")


def cert_msg(*ders):
    entries = b""
    for der in ders:
        entries += struct.pack(">I", len(der))[1:] + der
    return hs(11, struct.pack(">I", len(entries))[1:] + entries)


def main():
    der = open(DER, "rb").read()
    pkts = []
    ip_id = 1

    def send(src, dst, sport, dport, seq, ack, flags, payload=b""):
        nonlocal ip_id
        pkts.append(ip_pkt(src, dst,
                           tcp_pkt(sport, dport, seq, ack, flags, payload), ip_id))
        ip_id += 1

    def handshake(port):
        send(CLIENT_IP, SERVER_IP, 4444, port, C_SEQ, 0, 0x02)
        send(SERVER_IP, CLIENT_IP, port, 4444, S_SEQ, C_SEQ + 1, 0x12)
        send(CLIENT_IP, SERVER_IP, 4444, port, C_SEQ + 1, S_SEQ + 1, 0x10)
        return C_SEQ + 1, S_SEQ + 1

    # flow 1: two-certificate chain in three records
    c, s = handshake(8443)
    r = rec(22, client_hello())
    send(CLIENT_IP, SERVER_IP, 4444, 8443, c, s, 0x18, r)
    c += len(r)
    sh = rec(22, server_hello())
    send(SERVER_IP, CLIENT_IP, 8443, 4444, s, c, 0x18, sh)
    s += len(sh)
    full = cert_msg(der, der)
    n1 = 4 + 3 + 3 + 20  # header + chain len + cert len + a slice
    n2 = n1 + (len(der) - 20) + 3 + 40
    r1 = rec(22, full[:n1])
    r2 = rec(22, full[n1:n2])
    r3 = rec(22, full[n2:])
    send(SERVER_IP, CLIENT_IP, 8443, 4444, s, c, 0x18, r1)
    s += len(r1)
    send(SERVER_IP, CLIENT_IP, 8443, 4444, s, c, 0x18, r2)
    s += len(r2)
    send(SERVER_IP, CLIENT_IP, 8443, 4444, s, c, 0x18, r3)
    s += len(r3)
    shd = rec(22, hs(14, b""))
    send(SERVER_IP, CLIENT_IP, 8443, 4444, s, c, 0x18, shd)

    # flow 2: single-certificate chain in one record
    c, s = handshake(8444)
    r = rec(22, client_hello())
    send(CLIENT_IP, SERVER_IP, 4444, 8444, c, s, 0x18, r)
    c += len(r)
    sh = rec(22, server_hello())
    send(SERVER_IP, CLIENT_IP, 8444, 4444, s, c, 0x18, sh)
    s += len(sh)
    scert = rec(22, cert_msg(der))
    send(SERVER_IP, CLIENT_IP, 8444, 4444, s, c, 0x18, scert)
    s += len(scert)
    shd = rec(22, hs(14, b""))
    send(SERVER_IP, CLIENT_IP, 8444, 4444, s, c, 0x18, shd)

    with open(DST, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    print("wrote %s: %d packets" % (DST, len(pkts)))


if __name__ == "__main__":
    main()
