#!/usr/bin/env python3
import argparse
import os
import struct
import time


CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT1 = 40001
CLIENT_PORT2 = 40002
SERVER_PORT = 5900


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
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        65535,
        0,
        0,
    )
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    csum = checksum(pseudo + tcp + payload)
    tcp = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        65535,
        csum,
        0,
    )

    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0x4000,
        64,
        6,
        0,
        src,
        dst,
    )
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


def rfb_server_init(name_len, fill_byte=b"A"):
    pixel_format = struct.pack(
        "!BBBBHHHBBB3s",
        32,
        24,
        0,
        1,
        255,
        255,
        255,
        16,
        8,
        0,
        b"\x00\x00\x00",
    )
    name = fill_byte * name_len
    return struct.pack("!HH", 1024, 768) + pixel_format + struct.pack("!I", name_len) + name


def rfb_failure_reason(reason_len, fill_byte=b"B"):
    return struct.pack("!I", reason_len) + (fill_byte * reason_len)


def emit_stream(f, src_ip, dst_ip, src_port, dst_port, seq, ack, payload, ts):
    max_payload = 1400
    off = 0
    while off < len(payload):
        chunk = payload[off : off + max_payload]
        pkt = tcp_packet(src_ip, dst_ip, src_port, dst_port, seq + off, ack, 0x18, chunk)
        write_record(f, pkt, ts)
        ts += 0.0005
        off += len(chunk)
    return seq + len(payload), ts


def emit_server_stream_with_acks(f, cliport, server_seq, client_seq, payload, ts):
    max_payload = 1400
    off = 0
    while off < len(payload):
        chunk = payload[off : off + max_payload]
        pkt = tcp_packet(
            SERVER_IP,
            CLIENT_IP,
            SERVER_PORT,
            cliport,
            server_seq + off,
            client_seq,
            0x18,
            chunk,
        )
        write_record(f, pkt, ts)
        ts += 0.0005
        off += len(chunk)

        ack = tcp_packet(
            CLIENT_IP,
            SERVER_IP,
            cliport,
            SERVER_PORT,
            client_seq,
            server_seq + off,
            0x10,
        )
        write_record(f, ack, ts)
        ts += 0.0005
    return server_seq + len(payload), ts


def make_pcap(path, name_len, fill_byte=b"A"):
    cseq = 1000
    sseq = 9000
    ts = time.time()
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT1, SERVER_PORT, cseq, 0, 0x02), ts)
        cseq += 1
        ts += 0.001
        write_record(f, tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT1, sseq, cseq, 0x12), ts)
        sseq += 1
        ts += 0.001
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT1, SERVER_PORT, cseq, sseq, 0x10), ts)
        ts += 0.001

        for src_ip, dst_ip, src_port, dst_port, data in [
            (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT1, b"RFB 003.008\n"),
            (CLIENT_IP, SERVER_IP, CLIENT_PORT1, SERVER_PORT, b"RFB 003.008\n"),
            (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT1, b"\x01\x01"),
            (CLIENT_IP, SERVER_IP, CLIENT_PORT1, SERVER_PORT, b"\x01"),
            (CLIENT_IP, SERVER_IP, CLIENT_PORT1, SERVER_PORT, b"\x01"),
        ]:
            if src_ip == CLIENT_IP:
                cseq, ts = emit_stream(f, src_ip, dst_ip, src_port, dst_port, cseq, sseq, data, ts)
            else:
                sseq, ts = emit_stream(f, src_ip, dst_ip, src_port, dst_port, sseq, cseq, data, ts)

        sseq, ts = emit_server_stream_with_acks(f, CLIENT_PORT1, sseq, cseq, rfb_server_init(name_len, fill_byte), ts)


def make_failure_pcap(path, reason_len, fill_byte=b"B"):
    cseq = 1000
    sseq = 9000
    ts = time.time()
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT2, SERVER_PORT, cseq, 0, 0x02), ts)
        cseq += 1
        ts += 0.001
        write_record(f, tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT2, sseq, cseq, 0x12), ts)
        sseq += 1
        ts += 0.001
        write_record(f, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT2, SERVER_PORT, cseq, sseq, 0x10), ts)
        ts += 0.001

        for src_ip, dst_ip, src_port, dst_port, data in [
            (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT2, b"RFB 003.008\n"),
            (CLIENT_IP, SERVER_IP, CLIENT_PORT2, SERVER_PORT, b"RFB 003.008\n"),
        ]:
            if src_ip == CLIENT_IP:
                cseq, ts = emit_stream(f, src_ip, dst_ip, src_port, dst_port, cseq, sseq, data, ts)
            else:
                sseq, ts = emit_stream(f, src_ip, dst_ip, src_port, dst_port, sseq, cseq, data, ts)

        # RFB 3.7/3.8: number-of-security-types == 0, followed by a failure reason.
        sseq, ts = emit_server_stream_with_acks(f, CLIENT_PORT2, sseq, cseq, b"\x00" + rfb_failure_reason(reason_len, fill_byte), ts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--small-name-len", type=int, default=16)
    ap.add_argument("--large-name-len", type=int, default=8 * 1024 * 1024)
    ap.add_argument("--failure-len", type=int, default=0)
    ap.add_argument("--name-fill-byte", type=lambda x: int(x, 0), default=0x41)
    ap.add_argument("--failure-fill-byte", type=lambda x: int(x, 0), default=0x42)
    ap.add_argument("--suffix", default="")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    name_fill = bytes([args.name_fill_byte & 0xFF])
    failure_fill = bytes([args.failure_fill_byte & 0xFF])
    suffix = f"_{args.suffix}" if args.suffix else ""
    make_pcap(os.path.join(args.out_dir, f"rfb_name_{args.small_name_len}{suffix}.pcap"), args.small_name_len, name_fill)
    make_pcap(os.path.join(args.out_dir, f"rfb_name_{args.large_name_len}{suffix}.pcap"), args.large_name_len, name_fill)
    if args.failure_len > 0:
        make_failure_pcap(os.path.join(args.out_dir, f"rfb_failure_{args.failure_len}{suffix}.pcap"), args.failure_len, failure_fill)


if __name__ == "__main__":
    main()
