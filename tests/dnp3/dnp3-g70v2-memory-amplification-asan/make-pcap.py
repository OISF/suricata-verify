#!/usr/bin/env python3

import struct

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 49152
SERVER_PORT = 20000
DNP3_BLOCK_SIZE = 16
DNP3_APP_CHUNK_SIZE = 249
POINTS = 512


def dnp3_crc(data):
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return struct.pack("<H", (~crc) & 0xFFFF)


def add_crc(data):
    return data + dnp3_crc(data)


def dnp3_link_frame(app_data, segment, segments):
    transport = segment & 0x3F
    if segment == 0:
        transport |= 0x40
    if segment == segments - 1:
        transport |= 0x80

    user_data = bytes([transport]) + app_data
    length = 5 + len(user_data)
    header = b"\x05\x64" + bytes([length, 0xC4]) + struct.pack("<HH", 1, 2)

    frame = add_crc(header)
    for offset in range(0, len(user_data), DNP3_BLOCK_SIZE):
        frame += add_crc(user_data[offset:offset + DNP3_BLOCK_SIZE])
    return frame


def dnp3_request():
    # FIR|FIN, WRITE; G70V2, two-byte count, then minimal zero-sized points.
    application = b"\xC0\x02\x46\x02\x08" + struct.pack("<H", POINTS)
    application += b"\x00" * (12 * POINTS)
    chunks = [
        application[offset:offset + DNP3_APP_CHUNK_SIZE]
        for offset in range(0, len(application), DNP3_APP_CHUNK_SIZE)
    ]
    return [dnp3_link_frame(chunk, i, len(chunks)) for i, chunk in enumerate(chunks)]


def packet(ether, src, dst, sport, dport, seq, ack, flags, payload=b""):
    pkt = ether / IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, seq=seq, ack=ack, flags=flags
    )
    if payload:
        pkt /= Raw(payload)
    return pkt


def build_pcap():
    client_ether = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    server_ether = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    client_seq = 1000
    server_seq = 2000
    packets = []

    packets.append(packet(client_ether, CLIENT, SERVER, CLIENT_PORT, SERVER_PORT,
            client_seq, 0, "S"))
    client_seq += 1
    packets.append(packet(server_ether, SERVER, CLIENT, SERVER_PORT, CLIENT_PORT,
            server_seq, client_seq, "SA"))
    server_seq += 1
    packets.append(packet(client_ether, CLIENT, SERVER, CLIENT_PORT, SERVER_PORT,
            client_seq, server_seq, "A"))

    for frame in dnp3_request():
        packets.append(packet(client_ether, CLIENT, SERVER, CLIENT_PORT, SERVER_PORT,
                client_seq, server_seq, "PA", frame))
        client_seq += len(frame)

    packets.append(packet(server_ether, SERVER, CLIENT, SERVER_PORT, CLIENT_PORT,
            server_seq, client_seq, "A"))
    packets.append(packet(client_ether, CLIENT, SERVER, CLIENT_PORT, SERVER_PORT,
            client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(packet(server_ether, SERVER, CLIENT, SERVER_PORT, CLIENT_PORT,
            server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(packet(client_ether, CLIENT, SERVER, CLIENT_PORT, SERVER_PORT,
            client_seq, server_seq, "A"))

    for i, pkt in enumerate(packets):
        pkt.time = 1_700_000_000 + i / 1000
    return packets


def main():
    wrpcap("input.pcap", build_pcap())


if __name__ == "__main__":
    main()
