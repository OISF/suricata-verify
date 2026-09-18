#!/usr/bin/env python3
"""
Craft the TLS malformed-certificate firewall test pcap.

TCP 3-way handshake between 10.0.2.5 (client) and 172.16.0.10:443
(server), then:

  P4 client->server  TLS handshake record: a fully valid ClientHello
  P5 server->client  TLS handshake record: a fully valid ServerHello
  P6 client->server  TLS handshake record: a valid client Certificate
                     (the certificate body is the committed
                     client_cert.der), so the client track reaches the
                     client_cert phase (sid 1533)
  P7 server->client  TLS handshake record: a server Certificate message
                     with a 10-byte garbage "certificate" (not an ASN.1
                     SEQUENCE), so the certificate fails to decode
  P8 client->server  TCP FIN

tshark dissects the outer TLS records; P7's server certificate is
deliberately malformed (garbage DER).

A phase is entered at the message start: both hellos name their
phases and their completions hand the tracks over to the cert
phases, so server_cert carries the server track from the ServerHello
record on (sid 1532 fires there and on the certificate record). The
garbage certificate fails to decode and leaves the certificate data
incomplete, so the advance to server_data is never established
(sid 1536 never fires). The failure only consumes its bytes: the
rest of the flow is parsed and nothing is dropped (a decode failure
is not an app-layer error).

Run this script from its own test directory: the pcap is written to
input.pcap.
"""

import os
import socket
import struct

DST = "input.pcap"
CLIENT_CERT_DER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "client_cert.der")

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


def client_hello():
    random = bytes(range(32))
    ciphers = bytes.fromhex("13021303c02fc02cc02bc030")
    sni = b"example.com"
    sni_ext = b"\x00\x00" + struct.pack(">H", 16) + struct.pack(">H", 14) + \
        b"\x00" + struct.pack(">H", len(sni)) + sni
    exts = sni_ext
    body = b"\x03\x03" + random + b"\x00" + struct.pack(">H", len(ciphers)) + ciphers + \
        b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    return b"\x01" + struct.pack(">I", len(body))[1:] + body


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


def client_certificate():
    der = open(CLIENT_CERT_DER, "rb").read()
    if der[:2] != b"\x30\x82":
        raise SystemExit("client_cert.der does not look like an X.509 cert")
    # certificate list: total_length, then per cert: length + data (no
    # count byte - RFC 5246 / parser layout)
    chain = struct.pack(">I", len(der))[1:] + der
    body = b"\x0b" + struct.pack(">I", 3 + len(chain))[1:] + \
        struct.pack(">I", len(chain))[1:] + chain
    return rec(body)


def certificate_garbage():
    der = b"\x41" * 10  # not an ASN.1 SEQUENCE
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

    ch = rec(client_hello())
    sh = server_hello()
    ccert = client_certificate()
    cert = certificate_garbage()

    c_seq = C_SEQ + 1
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, S_SEQ + 1, 0x18, ch)
    c_seq += len(ch)
    s_seq = S_SEQ + 1
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, 0x18, sh)
    s_seq += len(sh)
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, 0x18, ccert)
    c_seq += len(ccert)
    send(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, 0x18, cert)
    s_seq += len(cert)
    send(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, 0x01, b"")

    with open(DST, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    print("wrote %s: %d packets (CH %d B, SH %d B, client cert %d B, garbage cert %d B)"
          % (DST, len(pkts), len(ch), len(sh), len(ccert), len(cert)))


if __name__ == "__main__":
    main()
