#!/usr/bin/env python3
"""Generate test.pcap for dnp3-lua-points-pairs.

One TCP connection carrying two complete DNP3 write requests. Request 1
carries a 33-point group-1 variation-1 object (above the 32-point eager
threshold, so the lua `points` value is the lazy userdata); request 2
carries a 32-point object of the same shape (at the threshold, so
`points` is the plain table copy). After each request the server ACKs
it and the client sends a pure ACK, so the request is parsed and
inspected before the next one is sent.
"""

from scapy.all import IP, TCP, Raw, wrpcap

OUTPUT = "test.pcap"

SRC_IP = "192.168.1.100"
DST_IP = "192.168.1.200"
SRC_PORT = 10000
DST_PORT = 20000

# DNP3 link-layer addresses
DNP3_SRC = 3
DNP3_DST = 2


def dnp3_crc(data):
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return ((~crc) & 0xFFFF).to_bytes(2, "little")


def object_points(count):
    """A `count`-point group-1 variation-1 (binary) object: range
    qualifier 0, start 1, stop count, packed into ceil(count/8) data
    bytes."""
    data_len = (count // 8) + 1
    return bytes([0x01, 0x01, 0x00, 0x01, count]) + bytes(data_len)


def build_frame(seq, points):
    # Transport header FIR+FIN and application control FIR+FIN: each
    # frame is a complete request. Function code 2 (Write) matches
    # dnp3_func:2.
    th = 0xC0 | (seq & 0x3F)
    app_ctrl = 0xC0 | (seq & 0x0F)
    user_data = bytes([th, app_ctrl, 0x02]) + object_points(points)

    # User data in 16-byte chunks, each followed by its CRC.
    chunks = []
    for i in range(0, len(user_data), 16):
        chunk = user_data[i:i + 16]
        chunks.append(chunk + dnp3_crc(chunk))

    length = 5 + len(user_data)
    ctrl = 0xC4  # DIR=1, PRM=1 (request, master -> outstation)
    header = bytes([0x05, 0x64, length, ctrl]) + DNP3_DST.to_bytes(2, "little") \
        + DNP3_SRC.to_bytes(2, "little")
    return header + dnp3_crc(header) + b"".join(chunks)


def main():
    cseq, sseq = 1000, 5000
    pkts = []

    def cli(flags, payload=b""):
        p = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT,
                                             flags=flags, seq=cseq, ack=sseq)
        return p / Raw(load=payload) if payload else p

    def srv(flags):
        return IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT,
                                                flags=flags, seq=sseq, ack=cseq)

    pkts.append(IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT,
                                                 flags="S", seq=cseq))
    cseq += 1
    pkts.append(IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT,
                                                 flags="SA", seq=sseq, ack=cseq))
    sseq += 1
    pkts.append(cli("A"))

    for seq, count in ((0, 33), (1, 32)):
        frame = build_frame(seq, count)
        pkts.append(cli("PA", frame))
        cseq += len(frame)
        pkts.append(srv("A"))
        pkts.append(cli("A"))
        pkts.append(srv("A"))
        pkts.append(cli("A"))

    pkts.append(cli("FA"))
    cseq += 1
    pkts.append(srv("FA"))
    sseq += 1
    pkts.append(cli("A"))

    base = 1700000000.0
    for i, p in enumerate(pkts):
        p.time = base + i * 0.01

    wrpcap(OUTPUT, pkts)
    print(f"Created {OUTPUT} with {len(pkts)} packets")


if __name__ == "__main__":
    main()
