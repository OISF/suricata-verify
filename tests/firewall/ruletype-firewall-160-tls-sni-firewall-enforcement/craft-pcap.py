#!/usr/bin/env python3
"""
Craft the TLS SNI firewall enforcement test pcap.

Four client->server sessions (10.0.2.5 -> 172.16.0.10), each a TCP
3-way handshake followed by a ClientHello:

  port 443   SNI "suricata.io"  - allowed by the flow-scoped SNI accept
  port 4443  SNI "evil.example" - not allowed: the negated SNI drop rule
                                  fires on the record that completes the
                                  hello (the drop is rule-scoped, so it
                                  alerts)
  port 4453  no SNI extension   - matches no SNI rule: the completing
                                  record is decided in the client
                                  certificate phase, where the implicit
                                  default policy (drop:flow) applies -
                                  a silent drop, no alert
  port 4463  SNI "suricata.io", the hello split over two records - the
                                  first fragment carries no SNI buffer
                                  and is accepted by the plain hello
                                  state accept; the completing record
                                  matches the flow-scoped accept

The ruleset mirrors the SNI example in the firewall user guide
(doc/userguide/firewall/firewall-example.rst), which is where the
enforcement point moved when the hello completion hand-over was
introduced: a ClientHello that completes without a flow-scoped accept
is decided in the certificate phase, not in the hello phase any more.

Run this script from its own test directory: the pcap is written to
input.pcap.
"""

import os
import socket
import struct

DST = "input.pcap"

CLIENT_IP = "10.0.2.5"
SERVER_IP = "172.16.0.10"

# the committed self-signed certificate (see the 153 test directory)
DER = os.path.join("..", "ruletype-firewall-153-tls-malformed-cert", "client_cert.der")

MAC_C = bytes.fromhex("aabbccddee01")
MAC_S = bytes.fromhex("aabbccddee02")

C_SEQ = 1000
S_SEQ = 5000

FRAG1 = 60  # bytes of the ClientHello body in the first record


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


def client_hello(sni=None):
    ciphers = b"\xc0\x2f"
    if sni is not None:
        list_len = 1 + 2 + len(sni)  # name type + name length + name
        sni_ext = b"\x00\x00" + struct.pack(">H", 2 + list_len) + \
            struct.pack(">H", list_len) + b"\x00" + struct.pack(">H", len(sni)) + sni
        exts = sni_ext
    else:
        exts = b""
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00" +
            struct.pack(">H", len(ciphers)) + ciphers + b"\x01\x00" +
            struct.pack(">H", len(exts)) + exts)
    return hs(1, body)


def server_hello():
    return hs(2, b"\x03\x03" + bytes(range(32, 64)) + bytes([32]) +
             bytes(range(96, 128)) + b"\xc0\x2f" + b"\x00")


def server_cert(der):
    entry = struct.pack(">I", len(der))[1:] + der
    return hs(11, struct.pack(">I", len(entry))[1:] + entry)


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
        """SYN/SYN-ACK/ACK for one session; returns the next sequences."""
        send(CLIENT_IP, SERVER_IP, 4444, port, C_SEQ, 0, 0x02)
        send(SERVER_IP, CLIENT_IP, port, 4444, S_SEQ, C_SEQ + 1, 0x12)
        send(CLIENT_IP, SERVER_IP, 4444, port, C_SEQ + 1, S_SEQ + 1, 0x10)
        return C_SEQ + 1, S_SEQ + 1

    def flight(port, c, s, fragmented=False):
        """client hello then the server flight; returns packet indexes
        (1-based) of the hello-completing record"""
        ch = client_hello(b"suricata.io")
        if fragmented:
            r1 = rec(22, ch[:FRAG1])
            r2 = rec(22, ch[FRAG1:])
            send(CLIENT_IP, SERVER_IP, 4444, port, c, s, 0x18, r1)
            c += len(r1)
            send(CLIENT_IP, SERVER_IP, 4444, port, c, s, 0x18, r2)
            c += len(r2)
        else:
            r = rec(22, ch)
            send(CLIENT_IP, SERVER_IP, 4444, port, c, s, 0x18, r)
            c += len(r)
        sh = rec(22, server_hello())
        send(SERVER_IP, CLIENT_IP, port, 4444, s, c, 0x18, sh)
        s += len(sh)
        scert = rec(22, server_cert(der))
        send(SERVER_IP, CLIENT_IP, port, 4444, s, c, 0x18, scert)
        s += len(scert)
        shd = rec(22, hs(14, b""))
        send(SERVER_IP, CLIENT_IP, port, 4444, s, c, 0x18, shd)
        s += len(shd)
        cke = hs(16, b"\x41" * 40)
        fin = hs(20, b"\x42" * 36)
        send(CLIENT_IP, SERVER_IP, 4444, port, c, s, 0x18,
             rec(22, cke) + rec(20, b"\x01") + rec(22, fin))

    # flow A: allowed SNI, full flight
    c, s = handshake(443)
    flight(443, c, s)

    # flow B: not allowed SNI, dropped on the completing record
    c, s = handshake(4443)
    r = rec(22, client_hello(b"evil.example"))
    send(CLIENT_IP, SERVER_IP, 4444, 4443, c, s, 0x18, r)

    # flow C: no SNI at all, dropped by the implicit default policy
    c, s = handshake(4453)
    r = rec(22, client_hello())
    send(CLIENT_IP, SERVER_IP, 4444, 4453, c, s, 0x18, r)

    # flow D: allowed SNI, hello in two records
    c, s = handshake(4463)
    flight(4463, c, s, fragmented=True)

    with open(DST, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    print("wrote %s: %d packets" % (DST, len(pkts)))


if __name__ == "__main__":
    main()
