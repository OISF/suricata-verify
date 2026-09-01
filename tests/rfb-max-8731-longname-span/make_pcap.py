#!/usr/bin/env python3
"""
Pcap generator for the rfb-max-8731-longname-span SV test (ticket #8731,
PR 16159).

Reproduces the out-of-bounds slice introduced in PR 16159 (v3.4) in the
TCServerInit branch: when the ServerInit name is longer than
app-layer.protocols.rfb.max-string-length (here the default 4096, set
explicitly) and spans multiple TCP segments, the parser's
    current = &rem[request.to_skip as usize..]
is out of bounds (rem holds only the in-buffer tail of the name, which
is shorter than to_skip) -> Rust panic in a non-unwindable FFI function
-> engine abort (remote DoS).

Handshake (RFB 3.8, security type 2 VNC auth - spec-compliant, so the
test is independent of the separate None-path security-result issue):
  - RFB 003.008 version exchange
  - server offers 1 security type: VNC auth (2); client selects it
  - 16-byte VNC challenge / 16-byte client response
  - security result: 4-byte big-endian 0 (OK) - the width modeled by
    both the parser's be_u32 and tshark's VNC dissector
  - client init: shared flag = 1
  - server init: 1024x768, 32bpp true colour, name of NAME_LEN (10000)
    'N' bytes (> cap), sent in 1400-byte TCP segments so it spans
    buffer boundaries
  - clean TCP close (EOF) so the transaction is logged.

A correct parser truncates the name to the cap (too_long_string) and
must not crash; the pending skip of the name tail must account for the
tail bytes already present in the input buffer.
"""
import os
import struct
import sys
import time

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 40000
SERVER_PORT = 5900

NAME_LEN = 10000            # > cap (4096): truncated, too_long_string
SEG_SIZE = 1400             # name spans buffer boundaries
CHALLENGE = bytes(range(16))
AUTH_RESPONSE = bytes(range(16, 32))
# 32bpp / 24 depth, true colour, 8-bit channels, no shifts
PIXEL_FORMAT = bytes([32, 24, 0, 1, 8, 0, 8, 0, 8, 0, 0, 0, 0, 0, 0, 0])
NAME = b"N" * NAME_LEN
SERVER_INIT = struct.pack("!HH", 1024, 768) + PIXEL_FORMAT + \
    struct.pack("!I", NAME_LEN) + NAME


def ip4(addr):
    return bytes(int(x) for x in addr.split("."))


def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b""):
    src = ip4(src_ip)
    dst = ip4(dst_ip)
    offset_flags = (5 << 12) | flags
    tcp = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    csum = checksum(pseudo + tcp + payload)
    tcp = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, 65535, csum, 0)

    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]

    if src_ip == CLIENT_IP:
        eth = SERVER_MAC + CLIENT_MAC + struct.pack("!H", 0x0800)
    else:
        eth = CLIENT_MAC + SERVER_MAC + struct.pack("!H", 0x0800)
    return eth + ip + tcp + payload


def write_record(f, packet, ts):
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    f.write(struct.pack("<IIII", sec, usec, len(packet), len(packet)))
    f.write(packet)


def cseg(f, cseq, sseq, payload, ts):
    """One client->server data segment plus the server's ACK."""
    write_record(f,
                 tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                            cseq, sseq, 0x18, payload), ts)
    cseq += len(payload)
    ts += 0.0005
    write_record(f,
                 tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                            sseq, cseq, 0x10), ts)
    return cseq, ts + 0.0005


def sseg(f, sseq, cseq, payload, ts):
    """One server->client data segment plus the client's ACK."""
    write_record(f,
                 tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                            sseq, cseq, 0x18, payload), ts)
    sseq += len(payload)
    ts += 0.0005
    write_record(f,
                 tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                            cseq, sseq, 0x10), ts)
    return sseq, ts + 0.0005


def sseg_1400(f, sseq, cseq, payload, ts):
    """Server stream in SEG_SIZE chunks (each chunk = one segment)."""
    off = 0
    while off < len(payload):
        chunk = payload[off:off + SEG_SIZE]
        sseq, ts = sseg(f, sseq, cseq, chunk, ts)
        off += SEG_SIZE
    return sseq, ts


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "rfb_longname_span.pcap"
    cseq = 1000
    sseq = 9000
    ts = time.time()
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        # TCP 3WHS
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                   cseq, 0, 0x02), ts)
        cseq += 1
        ts += 0.001
        write_record(f, tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                                   sseq, cseq, 0x12), ts)
        sseq += 1
        ts += 0.001
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                   cseq, sseq, 0x10), ts)
        ts += 0.001

        # RFB versions (3.8)
        sseq, ts = sseg(f, sseq, cseq, b"RFB 003.008\n", ts)
        cseq, ts = cseg(f, cseq, sseq, b"RFB 003.008\n", ts)

        # VNC auth handshake
        sseq, ts = sseg(f, sseq, cseq, b"\x01\x02", ts)      # 1 type: VNC auth
        cseq, ts = cseg(f, cseq, sseq, b"\x02", ts)          # client selects it
        sseq, ts = sseg(f, sseq, cseq, CHALLENGE, ts)        # 16-byte challenge
        cseq, ts = cseg(f, cseq, sseq, AUTH_RESPONSE, ts)    # 16-byte response
        sseq, ts = sseg(f, sseq, cseq, b"\x00\x00\x00\x00", ts)  # result OK (4B)
        cseq, ts = cseg(f, cseq, sseq, b"\x01", ts)          # shared flag = 1

        # server init with the long name, SEG_SIZE segments
        sseq, ts = sseg_1400(f, sseq, cseq, SERVER_INIT, ts)

        # clean close
        write_record(f, tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                                   sseq, cseq, 0x11), ts)
        ts += 0.001
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                   cseq, sseq + 1, 0x10), ts)
        cseq += 1
        ts += 0.001
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                   cseq, sseq + 1, 0x11), ts)
        ts += 0.001
        write_record(f, tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                                   sseq + 1, cseq + 1, 0x10), ts)

    print("wrote %s" % out)


if __name__ == "__main__":
    main()
