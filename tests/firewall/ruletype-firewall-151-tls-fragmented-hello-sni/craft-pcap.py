#!/usr/bin/env python3
"""
Craft the TLS fragmented-hello firewall test pcap.

TCP 3-way handshake between 10.0.2.5 (client) and 172.16.0.10:443
(server), then a ClientHello that is split across two TLS records:

  P3 client->server  TLS handshake record 1: the 4-byte handshake
                     header and the first 60 bytes of the ClientHello
                     message
  P4 client->server  TLS handshake record 2: the remaining 67 bytes
                     (completes the message, includes the SNI
                     extension "example.com")
  P5 client->server  TCP FIN

tshark dissects the two records as Client Hello (fragment) and
Client Hello (last fragment) and reassembles them.

The phase state must not advance until the handshake message is fully
buffered: the client_hello decision is therefore made only when the
SNI is available.

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

FRAG1 = 60  # handshake-header + first 60 body bytes in record 1


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


def client_hello():
    random = bytes(range(32))
    ciphers = bytes.fromhex("13021303c02fc02cc02bc030")
    sni = b"example.com"
    # ext_data = list_len(2) + list(1 + name_len(2) + 11)
    sni_ext = b"\x00\x00" + struct.pack(">H", 16) + struct.pack(">H", 14) + \
        b"\x00" + struct.pack(">H", len(sni)) + sni
    sv_ext = b"\x00\x2b" + struct.pack(">H", 5) + b"\x00\x03\x03\x04\x03\x03"
    ks = bytes(range(32))
    # ext_data = list_len(2) + entry(group(2) + key_len(2) + 32)
    ks_ext = b"\x00\x33" + struct.pack(">H", 37) + struct.pack(">H", 35) + \
        b"\x00\x1d" + struct.pack(">H", 32) + ks
    exts = sni_ext + sv_ext + ks_ext
    body = b"\x03\x03" + random + b"\x00" + struct.pack(">H", len(ciphers)) + ciphers + \
        b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    # 1-byte type, 3-byte length, body
    return b"\x01" + struct.pack(">I", len(body))[1:] + body


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

    hs = client_hello()
    rec1 = b"\x16\x03\x03" + struct.pack(">H", len(hs[:FRAG1])) + hs[:FRAG1]
    rec2 = b"\x16\x03\x03" + struct.pack(">H", len(hs[FRAG1:])) + hs[FRAG1:]

    c_seq = C_SEQ + 1
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, S_SEQ + 1, 0x18, rec1)
    c_seq += len(rec1)
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, S_SEQ + 1, 0x18, rec2)
    c_seq += len(rec2)
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, S_SEQ + 1, 0x01, b"")

    with open(DST, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    print("wrote %s: %d packets, ClientHello %d bytes in 2 records (%d+%d)"
          % (DST, len(pkts), len(hs), FRAG1, len(hs) - FRAG1))


if __name__ == "__main__":
    main()
