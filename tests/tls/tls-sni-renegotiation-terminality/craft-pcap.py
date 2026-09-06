#!/usr/bin/env python3
"""
Craft the TLS SNI renegotiation-terminality pcap.

Takes the completed handshake of tls-client-hello-frag-01/dump_mtu300.pcap
(client SNI www.google.com, flow ends at a close_notify exchange) and
appends a TLS 1.2 renegotiation exchange:

  P63 server->client  ServerHello with the renegotiation_info extension
  P64 server->client  ChangeCipherSpec
  P65 client->server  ClientHello with SNI "reneg.example.com"
  P66 server->client  (opaque, stands in for the encrypted Finished)

At the point of P65 the client track has long advanced past the
client_hello phase (client_data since handshake completion), so the
renegotiation SNI arrives *after* the client_hello window closed.

The appended packets continue the TCP sequence numbers of the original
flow; no crypto is performed (the parser is a state machine).

Run this script from its own test directory: SRC and DST paths are
cwd-relative.
"""

import socket
import struct
import sys

SRC = "../../tls/tls-client-hello-frag-01/dump_mtu300.pcap"
DST = "input.pcap"

RENAM_SNI = b"reneg.example.com"


def csum16(buf):
    if len(buf) % 2:
        buf += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(buf) // 2), buf))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ip_pkt(src, dst, payload, ip_id, mac_s, mac_d):
    l4 = socket.IPPROTO_TCP
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ip_id, 0, 64, l4,
                      0, socket.inet_aton(src), socket.inet_aton(dst))
    ck = csum16(hdr)
    hdr = hdr[:10] + struct.pack(">H", ck) + hdr[12:]
    return mac_d + mac_s + b"\x08\x00" + hdr + payload


def tls_record(rtype, version, body):
    return struct.pack(">BHH", rtype, version, len(body)) + body


def main():
    d = open(SRC, "rb").read()
    if d[:4] != b"\xd4\xc3\xb2\xa1":
        sys.exit("expected classic little-endian pcap")

    off = 24
    n_toclient = (0, 0)   # (next_seq, ack) for server->client direction
    n_toserver = (0, 0)   # (next_seq, ack) for client->server direction
    mac_client = None
    mac_server = None
    last_id = 0
    while off < len(d):
        ts_s, ts_us, incl, _ = struct.unpack("<IIII", d[off:off + 16])
        f = d[off + 16:off + 16 + incl]
        mac_s, mac_d = f[:6], f[6:12]
        if mac_client is None:
            mac_client, mac_server = mac_s, mac_d
        ip = f[14:34]
        src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        last_id = struct.unpack(">H", ip[4:6])[0]
        tcp = f[34:54]
        sport, dport, seq, ack = struct.unpack(">HHII", tcp[:12])
        plen = len(f) - 54
        if dst == "142.251.111.105":  # toserver: client is src
            n_toserver = (seq + plen, ack)
            mac_client, mac_server = mac_s, mac_d
        else:  # toclient
            n_toclient = (seq + plen, ack)
            mac_client, mac_server = mac_d, mac_s
        off += 16 + incl

    tseq, task = n_toserver
    sseq, sack = n_toclient

    def tcp_payload(sport, dport, seq, ack, payload):
        if sport == 443:
            src_ip, dst_ip = "142.251.111.105", "10.20.0.14"
        else:
            src_ip, dst_ip = "10.20.0.14", "142.251.111.105"
        hdr = struct.pack(">HHIIH", sport, dport, seq, ack, (5 << 12) | 0x18)
        hdr += struct.pack(">HHH", 65535, 0, 0)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + \
            struct.pack(">BH", 6, len(hdr) + len(payload))
        ck = csum16(pseudo + hdr + payload)
        return hdr[:16] + struct.pack(">H", ck) + hdr[18:] + payload

    # P63: server ServerHello with renegotiation_info
    # renegotiation_info: a single context_length byte (0), no verify_data
    ext_reneg = struct.pack(">HH", 0xff01, 1) + b"\x00"
    ext_block = struct.pack(">H", len(ext_reneg)) + ext_reneg
    sh_body = (struct.pack(">H", 0x0303) + b"\x11" * 32 +
               struct.pack(">B", 32) + b"\x00" * 32 +
               struct.pack(">H", 0x002f) + b"\x00" + ext_block)
    sh_hs = struct.pack(">B", 2) + struct.pack(">I", len(sh_body))[1:] + sh_body
    p63 = tcp_payload(443, 38576, sseq, sack, tls_record(22, 0x0303, sh_hs))
    sseq += len(p63) - 20

    # P64: server ChangeCipherSpec
    p64 = tcp_payload(443, 38576, sseq, sack, tls_record(20, 0x0303, b"\x01"))
    sseq += len(p64) - 20

    # P65: client ClientHello, SNI = reneg.example.com
    # sni_list = [type(1)][name_len(2)][name]; ext data = list_len(2) + list
    sni_data = struct.pack(">H", 1 + 2 + len(RENAM_SNI)) + \
               b"\x00" + struct.pack(">H", len(RENAM_SNI)) + RENAM_SNI
    sni_ext = struct.pack(">HH", 0x0000, len(sni_data)) + sni_data
    exts = struct.pack(">H", len(sni_ext)) + sni_ext
    ch_body = (struct.pack(">H", 0x0301) + b"\x22" * 32 +
               struct.pack(">B", 32) + b"\x00" * 32 +
               struct.pack(">H", 4) + struct.pack(">HH", 0x002f, 0x0035) +
               struct.pack(">BB", 1, 0) + exts)
    ch_hs = struct.pack(">B", 1) + struct.pack(">I", len(ch_body))[1:] + ch_body
    p65 = tcp_payload(38576, 443, tseq, task, tls_record(22, 0x0301, ch_hs))
    tseq += len(p65) - 20

    # P66: opaque Finished stand-in
    p66 = tcp_payload(443, 38576, sseq, sack, tls_record(23, 0x0303, b"\xaa" * 12))

    out = d  # full original pcap: global header + all original packets
    ts_base = ts_s
    for i, (mac_s, mac_d, src, dst, payload, ip_id) in enumerate([
            (mac_server, mac_client, "142.251.111.105", "10.20.0.14", p63, last_id + 1),
            (mac_server, mac_client, "142.251.111.105", "10.20.0.14", p64, last_id + 2),
            (mac_client, mac_server, "10.20.0.14", "142.251.111.105", p65, last_id + 3),
            (mac_server, mac_client, "142.251.111.105", "10.20.0.14", p66, last_id + 4)]):
        frame = ip_pkt(src, dst, payload, ip_id, mac_s, mac_d)
        out += struct.pack("<IIII", ts_base, 0, len(frame), len(frame)) + frame

    open(DST, "wb").write(out)
    print("wrote %s (66 packets: 62 original + 4 renegotiation)" % DST)


if __name__ == "__main__":
    main()
