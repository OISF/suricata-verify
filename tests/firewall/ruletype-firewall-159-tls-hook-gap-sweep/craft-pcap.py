#!/usr/bin/env python3
"""
Craft the TLS hook-gap firewall test pcap.

The same mTLS 1.2 flight as ruletype-firewall-158-tls-mtls-flight-order,
in standard order:

    C->S  ClientHello
    S->C  ServerHello                    (pkt 5)
    S->C  Certificate (server, valid)    (pkt 6)
    S->C  CertificateRequest + ServerHelloDone  (pkt 7)
    C->S  Certificate (client, valid), first fragment (pkt 8)
    C->S  Certificate continuation, completes the message (pkt 9)
    C->S  ClientKeyExchange + CCS + Finished    (pkt 10)

The point here is the pairing with the sparse rules in firewall.rules:
no rule on client_data, so around the client_cert hook the
missing-progress flag applies. The ClientHello packet advances the
client track to client_cert, where sid 11 is evaluated with an empty
certificate buffer (rule-no-match default policy path); the packet
that completes the client certificate is where sid 11 matches (rule-
match path). This pcap supplies both passes.

Certificate bodies are the committed self-signed client_cert.der
(via the 153 test directory), used for both sides.

Run from its own test directory; writes input.pcap.
"""

import os
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

DER = os.path.join("..", "ruletype-firewall-153-tls-malformed-cert", "client_cert.der")


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


def tcp_seg(sport, dport, seq, ack, flags, payload):
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    hdr = hdr[:16] + struct.pack(">H", csum16(hdr + payload)) + hdr[18:]
    return hdr + payload


def hs(t, body):
    return bytes([t]) + struct.pack(">I", len(body))[1:] + body


def rec(ct, payload):
    return bytes([ct]) + b"\x03\x03" + struct.pack(">H", len(payload)) + payload


def cert_msg():
    der = open(DER, "rb").read()
    entry = struct.pack(">I", len(der))[1:] + der
    return hs(11, struct.pack(">I", len(entry))[1:] + entry)


def main():
    pkts = []
    ip_id = 1

    def send(src, dst, sport, dport, seq, ack, flags, payload=b""):
        nonlocal ip_id
        pkts.append(ip_pkt(src, dst, tcp_seg(sport, dport, seq, ack, flags, payload), ip_id))
        ip_id += 1

    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ, 0, 0x02)
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ, C_SEQ + 1, 0x12)
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1, S_SEQ + 1, 0x10)

    ch = hs(1, b"\x03\x03" + bytes(range(32)) + b"\x00" +
            struct.pack(">H", 2) + b"\xc0\x2f" + b"\x01\x00" + struct.pack(">H", 0))
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, C_SEQ + 1, S_SEQ + 1, 0x18,
         rec(22, ch))
    c = C_SEQ + 1 + 5 + len(ch)

    sh = hs(2, b"\x03\x03" + bytes(range(32, 64)) + bytes([32]) + bytes(range(96, 128)) +
            b"\xc0\x2f" + b"\x00")
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, S_SEQ + 1, c, 0x18, rec(22, sh))
    s = S_SEQ + 1 + 5 + len(sh)

    scert = rec(22, cert_msg())
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s, c, 0x18, scert)
    s += len(scert)

    certreq = hs(13, b"\x01\x00" + b"\x00\x02\x04\x03" + b"\x00\x00")
    shd = hs(14, b"")
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s, c, 0x18,
         rec(22, certreq) + rec(22, shd))
    s += 5 + len(certreq) + 5 + len(shd)

    # the client certificate is split over two records/packets: the
    # first carries the message header and part of the chain, so on
    # that packet the client track has entered client_cert without
    # completing it: a plain state accept decides it (fragments in
    # flight). A cross-track data shortcut would hide that: the
    # fragment packet would already be decided in client_data.
    ccert_full = cert_msg()
    n = 4 + 3 + 3 + 20  # header + chain len + cert len + a slice
    ccert1 = rec(22, ccert_full[:n])
    ccert2 = rec(22, ccert_full[n:])
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c, s, 0x18, ccert1)
    c += len(ccert1)
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c, s, 0x18, ccert2)
    c += len(ccert2)

    cke = hs(16, b"\x41" * 40)
    fin = hs(20, b"\x42" * 36)
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c, s, 0x18,
         rec(22, cke) + rec(20, b"\x01") + rec(22, fin))

    with open("input.pcap", "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    print("wrote input.pcap: %d packets" % len(pkts))


if __name__ == "__main__":
    main()
