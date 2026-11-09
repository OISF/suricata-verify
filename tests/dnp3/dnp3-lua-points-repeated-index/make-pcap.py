#!/usr/bin/env python3
"""Generate test.pcap for dnp3-lua-points-repeated-index.

One TCP connection carrying one DNP3 write request whose single
16384-point group-1 variation-1 object (the parser's default
max-points bound) is reassembled from nine max-sized (link length
255) transport segments: FIR on the first, the transport sequence in
between, FIN on the last. The point count exceeds the 32-point eager
threshold, so the lua `points` value is the lazy userdata.
"""

import struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap

OUTPUT = "test.pcap"

SRC_IP = "192.168.1.100"
DST_IP = "192.168.1.200"
SRC_PORT = 10000
DST_PORT = 20000

DNP3_SRC = 3
DNP3_DST = 2

POINT_COUNT = 16384
DNP3_BLOCK_SIZE = 16
DNP3_CRC_LEN = 2

ETH_C2S = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ETH_S2C = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")

CRC_TABLE = [
    0x0000, 0x365e, 0x6cbc, 0x5ae2, 0xd978, 0xef26, 0xb5c4, 0x839a,
    0xff89, 0xc9d7, 0x9335, 0xa56b, 0x26f1, 0x10af, 0x4a4d, 0x7c13,
    0xb26b, 0x8435, 0xded7, 0xe889, 0x6b13, 0x5d4d, 0x07af, 0x31f1,
    0x4de2, 0x7bbc, 0x215e, 0x1700, 0x949a, 0xa2c4, 0xf826, 0xce78,
    0x29af, 0x1ff1, 0x4513, 0x734d, 0xf0d7, 0xc689, 0x9c6b, 0xaa35,
    0xd626, 0xe078, 0xba9a, 0x8cc4, 0x0f5e, 0x3900, 0x63e2, 0x55bc,
    0x9bc4, 0xad9a, 0xf778, 0xc126, 0x42bc, 0x74e2, 0x2e00, 0x185e,
    0x644d, 0x5213, 0x08f1, 0x3eaf, 0xbd35, 0x8b6b, 0xd189, 0xe7d7,
    0x535e, 0x6500, 0x3fe2, 0x09bc, 0x8a26, 0xbc78, 0xe69a, 0xd0c4,
    0xacd7, 0x9a89, 0xc06b, 0xf635, 0x75af, 0x43f1, 0x1913, 0x2f4d,
    0xe135, 0xd76b, 0x8d89, 0xbbd7, 0x384d, 0x0e13, 0x54f1, 0x62af,
    0x1ebc, 0x28e2, 0x7200, 0x445e, 0xc7c4, 0xf19a, 0xab78, 0x9d26,
    0x7af1, 0x4caf, 0x164d, 0x2013, 0xa389, 0x95d7, 0xcf35, 0xf96b,
    0x8578, 0xb326, 0xe9c4, 0xdf9a, 0x5c00, 0x6a5e, 0x30bc, 0x06e2,
    0xc89a, 0xfec4, 0xa426, 0x9278, 0x11e2, 0x27bc, 0x7d5e, 0x4b00,
    0x3713, 0x014d, 0x5baf, 0x6df1, 0xee6b, 0xd835, 0x82d7, 0xb489,
    0xa6bc, 0x90e2, 0xca00, 0xfc5e, 0x7fc4, 0x499a, 0x1378, 0x2526,
    0x5935, 0x6f6b, 0x3589, 0x03d7, 0x804d, 0xb613, 0xecf1, 0xdaaf,
    0x14d7, 0x2289, 0x786b, 0x4e35, 0xcdaf, 0xfbf1, 0xa113, 0x974d,
    0xeb5e, 0xdd00, 0x87e2, 0xb1bc, 0x3226, 0x0478, 0x5e9a, 0x68c4,
    0x8f13, 0xb94d, 0xe3af, 0xd5f1, 0x566b, 0x6035, 0x3ad7, 0x0c89,
    0x709a, 0x46c4, 0x1c26, 0x2a78, 0xa9e2, 0x9fbc, 0xc55e, 0xf300,
    0x3d78, 0x0b26, 0x51c4, 0x679a, 0xe400, 0xd25e, 0x88bc, 0xbee2,
    0xc2f1, 0xf4af, 0xae4d, 0x9813, 0x1b89, 0x2dd7, 0x7735, 0x416b,
    0xf5e2, 0xc3bc, 0x995e, 0xaf00, 0x2c9a, 0x1ac4, 0x4026, 0x7678,
    0x0a6b, 0x3c35, 0x66d7, 0x5089, 0xd313, 0xe54d, 0xbfaf, 0x89f1,
    0x4789, 0x71d7, 0x2b35, 0x1d6b, 0x9ef1, 0xa8af, 0xf24d, 0xc413,
    0xb800, 0x8e5e, 0xd4bc, 0xe2e2, 0x6178, 0x5726, 0x0dc4, 0x3b9a,
    0xdc4d, 0xea13, 0xb0f1, 0x86af, 0x0535, 0x336b, 0x6989, 0x5fd7,
    0x23c4, 0x159a, 0x4f78, 0x7926, 0xfabc, 0xcce2, 0x9600, 0xa05e,
    0x6e26, 0x5878, 0x029a, 0x34c4, 0xb75e, 0x8100, 0xdbe2, 0xedbc,
    0x91af, 0xa7f1, 0xfd13, 0xcb4d, 0x48d7, 0x7e89, 0x246b, 0x1235,
]


def dnp3_crc(data):
    c = 0
    for b in data:
        idx = (c ^ b) & 0xff
        c = (CRC_TABLE[idx] ^ (c >> 8)) & 0xffff
    return (~c) & 0xffff


def with_crc(data):
    c = dnp3_crc(data)
    return data + bytes([c & 0xff, c >> 8])


def dnp3_frame(user_data):
    # Link header length includes control, dst, src, and user data,
    # but no CRCs. Max-sized segments keep it at 255.
    link_len = 5 + len(user_data)
    assert link_len <= 255
    ctrl = 0xC4  # DIR=1, PRM=1 (request, master -> outstation)
    hdr_no_crc = (b"\x05\x64" + bytes([link_len, ctrl])
                  + struct.pack("<HH", DNP3_DST, DNP3_SRC))
    out = with_crc(hdr_no_crc)
    for i in range(0, len(user_data), DNP3_BLOCK_SIZE):
        out += with_crc(user_data[i:i + DNP3_BLOCK_SIZE])
    return out


def object_user_data():
    """The reassembled application data: application control
    FIR|FIN + function code 2 (Write) + one 16384-point group-1
    variation-1 object: Suricata's 3-byte object header (group,
    variation, qualifier with prefix 1 = 2-octet start/stop), start 1,
    stop 16384, and (count/8)+1 data bytes per the G1V1 decoder."""
    app_header = b"\xc0\x02"
    object_header = (b"\x01\x01\x01"
                     + (1).to_bytes(2, "little")
                     + (POINT_COUNT).to_bytes(2, "little"))
    return app_header + object_header + bytes(POINT_COUNT // 8 + 1)


def split_segments(user_data):
    """Cut the application data into 249-byte chunks (plus the 1-byte
    transport header each: link length 255) - FIR on the first, the
    transport sequence in between, FIN on the last."""
    segs = []
    i = 0
    for off in range(0, len(user_data), 249):
        chunk = user_data[off:off + 249]
        last = off + len(chunk) >= len(user_data)
        th = 0
        if i == 0:
            th |= 0x40  # FIR
        if last:
            th |= 0x80  # FIN
        th |= i % 64
        segs.append(bytes([th]) + chunk)
        i += 1
    return segs


def packet(src, sport, dst, dport, seq, ack, payload=b"", flags="PA"):
    eth = ETH_C2S if src == SRC_IP else ETH_S2C
    return (eth.copy() / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
            / Raw(payload))


def main():
    pkts = []
    cseq, sseq = 1000, 5000
    pkts.append(packet(SRC_IP, SRC_PORT, DST_IP, DST_PORT, cseq, sseq,
                       flags="S"))
    cseq += 1
    pkts.append(packet(DST_IP, DST_PORT, SRC_IP, SRC_PORT, sseq, cseq,
                       flags="SA"))
    sseq += 1
    pkts.append(packet(SRC_IP, SRC_PORT, DST_IP, DST_PORT, cseq, sseq,
                       flags="A"))

    for seg in split_segments(object_user_data()):
        frame = dnp3_frame(seg)
        pkts.append(packet(SRC_IP, SRC_PORT, DST_IP, DST_PORT, cseq, sseq,
                           frame))
        cseq += len(frame)
        pkts.append(packet(DST_IP, DST_PORT, SRC_IP, SRC_PORT, sseq, cseq,
                           flags="A"))

    pkts.append(packet(SRC_IP, SRC_PORT, DST_IP, DST_PORT, cseq, sseq,
                       flags="FA"))
    cseq += 1
    pkts.append(packet(DST_IP, DST_PORT, SRC_IP, SRC_PORT, sseq, cseq,
                       flags="FA"))
    sseq += 1
    pkts.append(packet(SRC_IP, SRC_PORT, DST_IP, DST_PORT, cseq, sseq,
                       flags="A"))

    base = 1700000000.0
    for i, p in enumerate(pkts):
        p.time = base + i * 0.01

    wrpcap(OUTPUT, pkts)
    print(f"Created {OUTPUT} with {len(pkts)} packets")


if __name__ == "__main__":
    main()
