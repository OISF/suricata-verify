#!/usr/bin/env python3
"""
Pcap generator for the rfb-max-8731-toskip SV test (ticket #8731, PR 16145).

Traffic:
  - RFB handshake (versions 3.8)
  - server sends security-types count = 0 followed by a failure reason of
    REASON_LEN (5000) bytes in a SINGLE segment (larger than the
    max-string-length cap of 1024 used in test.yaml)
  - server sends a second, well-formed failure reason of 10 bytes
    ("0123456789") in a second segment. The RFB parser stays in the
    TCFailureReason state and must re-parse it (it must not be swallowed by
    the parser's pending to_skip bookkeeping).
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

REASON_LEN = 5000          # > cap (1024): truncated, too_long_string
SECOND_REASON = b"0123456789"  # 10 bytes, well-formed, must be parsed


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


def server_segment(f, sseq, cseq, payload, ts):
    """One server->client data segment plus the client's ACK."""
    write_record(f,
                 tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                            sseq, cseq, 0x18, payload), ts)
    ts += 0.0005
    write_record(f,
                 tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                            cseq, sseq + len(payload), 0x10), ts)
    return sseq + len(payload), ts + 0.0005


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "rfb_trunc_toskip.pcap"
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
        sseq, ts = server_segment(f, sseq, cseq, b"RFB 003.008\n", ts)
        # client version, client->server
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                                   cseq, sseq, 0x18, b"RFB 003.008\n"), ts)
        cseq += 12
        ts += 0.0005
        write_record(f, tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                                   sseq, cseq, 0x10), ts)
        ts += 0.0005

        # 0 security types + 5000-byte failure reason, ONE segment
        reason1 = struct.pack("!I", REASON_LEN) + b"A" * REASON_LEN
        sseq, ts = server_segment(f, sseq, cseq, b"\x00" + reason1, ts)

        # second, well-formed 10-byte failure reason, ONE segment
        reason2 = struct.pack("!I", len(SECOND_REASON)) + SECOND_REASON
        sseq, ts = server_segment(f, sseq, cseq, reason2, ts)

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
