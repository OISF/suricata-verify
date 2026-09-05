#!/usr/bin/env python3
"""
Pcap generator for the rfb-none-secresult SV test.

Bug: the RFB parser skips the security result on the "None" (security
type 1) path. After the client selects type 1 it expects the client's
shared flag and then the ServerInit, but a spec-compliant RFB 3.8 server
sends a security result first (0 = OK, 1 = failure + reason). The
unconsumed result bytes collide with the parser's state machine (the
result arrives on ToClient while the state is TSClientInit, a
ToServer-only state), trigger the "Invalid state for response"
catch-all, log a confused_state anomaly and discard the rest of the
handshake (shared flag + ServerInit).

Handshake generated here (RFB 3.8, security type 1 "None"):
  - RFB 003.008 version exchange
  - server offers 1 security type: None (1)
  - client selects type 1
  - security result: 4-byte big-endian 0 (OK). 4-byte width is the
    layout both dissectors model: the parser's be_u32
    (parse_security_result) and tshark's VNC dissector
    (tvb_get_ntohl, packet-vnc.c)
  - client init: shared flag = 1
  - server init: 1920x1080, 32bpp true colour, name "test"
  - clean TCP close (EOF) so the transaction is logged.
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

# 32bpp / 24 depth, true colour, 8-bit channels, no shifts
PIXEL_FORMAT = bytes([32, 24, 0, 1, 8, 0, 8, 0, 8, 0, 0, 0, 0, 0, 0, 0])
NAME = b"test"
SERVER_INIT = struct.pack("!HH", 1920, 1080) + PIXEL_FORMAT + \
    struct.pack("!I", len(NAME)) + NAME


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


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "rfb_none_secresult.pcap"
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

        # server offers one security type: None (1); client selects it
        sseq, ts = sseg(f, sseq, cseq, b"\x01\x01", ts)
        cseq, ts = cseg(f, cseq, sseq, b"\x01", ts)

        # security result: 4-byte big-endian 0 (OK)
        sseq, ts = sseg(f, sseq, cseq, b"\x00\x00\x00\x00", ts)

        # client init: shared flag = 1
        cseq, ts = cseg(f, cseq, sseq, b"\x01", ts)

        # server init
        sseq, ts = sseg(f, sseq, cseq, SERVER_INIT, ts)

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
