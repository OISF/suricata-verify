#!/usr/bin/env python3
# Generates input.pcap: 2 DNP3 flows validating fail-closed behaviour when a
# flow dies while the only candidate LTE (auto-accept-prior-states) rule is
# still provisional (no-match not yet definitive: no CANT_MATCH, tx below
# its end state).
#
# The LTE rule (sid 211) waits for a marker in the re-assembled DNP3
# application buffer (hook request_started, progress 0 while the message
# is still being reassembled).
#
# * flow A (49370) sends the full two-frame message (FIR + FIN) with the
#   marker "DNP3ABORTMARK" split over the frames: the message completes,
#   the marker is in the buffer and the rule matches (accept:flow), 0
#   drops;
# * flow B (49371) sends only the first frame (FIR, no FIN) and then
#   RSTs: the message never completes, the request tx stays at progress 0
#   (request_started, reassembly in progress), below its end state. The
#   engine's no match is still "provisional" by its own eof test (progress
#   0 == registered progress 0) when the flow is torn down. On the final
#   PKT_PSEUDO_STREAM_END pass the no match must be treated as definitive
#   and the per-hook default app policy must apply - before the fix the
#   flow died with no firewall verdict (0 drops).
#
# Expected: exactly 1 `firewall default app policy` drop (flow B).
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "142.251.111.105"  # $HOME_NET -> $EXTERNAL_NET
DP = 20000

DNP3_CRC_TABLE = [
    0x0, 0x365e, 0x6cbc, 0x5ae2, 0xd978, 0xef26, 0xb5c4, 0x839a,
    0xff89, 0xc9d7, 0x9335, 0xa56b, 0x26f1, 0x10af, 0x4a4d, 0x7c13,
    0xb26b, 0x8435, 0xded7, 0xe889, 0x6b13, 0x5d4d, 0x7af, 0x31f1,
    0x4de2, 0x7bbc, 0x215e, 0x1700, 0x949a, 0xa2c4, 0xf826, 0xce78,
    0x29af, 0x1ff1, 0x4513, 0x734d, 0xf0d7, 0xc689, 0x9c6b, 0xaa35,
    0xd626, 0xe078, 0xba9a, 0x8cc4, 0xf5e, 0x3900, 0x63e2, 0x55bc,
    0x9bc4, 0xad9a, 0xf778, 0xc126, 0x42bc, 0x74e2, 0x2e00, 0x185e,
    0x644d, 0x5213, 0x8f1, 0x3eaf, 0xbd35, 0x8b6b, 0xd189, 0xe7d7,
    0x535e, 0x6500, 0x3fe2, 0x9bc, 0x8a26, 0xbc78, 0xe69a, 0xd0c4,
    0xacd7, 0x9a89, 0xc06b, 0xf635, 0x75af, 0x43f1, 0x1913, 0x2f4d,
    0xe135, 0xd76b, 0x8d89, 0xbbd7, 0x384d, 0xe13, 0x54f1, 0x62af,
    0x1ebc, 0x28e2, 0x7200, 0x445e, 0xc7c4, 0xf19a, 0xab78, 0x9d26,
    0x7af1, 0x4caf, 0x164d, 0x2013, 0xa389, 0x95d7, 0xcf35, 0xf96b,
    0x8578, 0xb326, 0xe9c4, 0xdf9a, 0x5c00, 0x6a5e, 0x30bc, 0x6e2,
    0xc89a, 0xfec4, 0xa426, 0x9278, 0x11e2, 0x27bc, 0x7d5e, 0x4b00,
    0x3713, 0x14d, 0x5baf, 0x6df1, 0xee6b, 0xd835, 0x82d7, 0xb489,
    0xa6bc, 0x90e2, 0xca00, 0xfc5e, 0x7fc4, 0x499a, 0x1378, 0x2526,
    0x5935, 0x6f6b, 0x3589, 0x3d7, 0x804d, 0xb613, 0xecf1, 0xdaaf,
    0x14d7, 0x2289, 0x786b, 0x4e35, 0xcdaf, 0xfbf1, 0xa113, 0x974d,
    0xeb5e, 0xdd00, 0x87e2, 0xb1bc, 0x3226, 0x478, 0x5e9a, 0x68c4,
    0x8f13, 0xb94d, 0xe3af, 0xd5f1, 0x566b, 0x6035, 0x3ad7, 0xc89,
    0x709a, 0x46c4, 0x1c26, 0x2a78, 0xa9e2, 0x9fbc, 0xc55e, 0xf300,
    0x3d78, 0xb26, 0x51c4, 0x679a, 0xe400, 0xd25e, 0x88bc, 0xbee2,
    0xc2f1, 0xf4af, 0xae4d, 0x9813, 0x1b89, 0x2dd7, 0x7735, 0x416b,
    0xf5e2, 0xc3bc, 0x995e, 0xaf00, 0x2c9a, 0x1ac4, 0x4026, 0x7678,
    0xa6b, 0x3c35, 0x66d7, 0x5089, 0xd313, 0xe54d, 0xbfaf, 0x89f1,
    0x4789, 0x71d7, 0x2b35, 0x1d6b, 0x9ef1, 0xa8af, 0xf24d, 0xc413,
    0xb800, 0x8e5e, 0xd4bc, 0xe2e2, 0x6178, 0x5726, 0xdc4, 0x3b9a,
    0xdc4d, 0xea13, 0xb0f1, 0x86af, 0x535, 0x336b, 0x6989, 0x5fd7,
    0x23c4, 0x159a, 0x4f78, 0x7926, 0xfabc, 0xcce2, 0x9600, 0xa05e,
    0x6e26, 0x5878, 0x29a, 0x34c4, 0xb75e, 0x8100, 0xdbe2, 0xedbc,
    0x91af, 0xa7f1, 0xfd13, 0xcb4d, 0x48d7, 0x7e89, 0x246b, 0x1235
]

def dnp3_crc(data):
    crc = 0
    for b in data:
        crc = (DNP3_CRC_TABLE[(crc ^ b) & 0xff] ^ (crc >> 8)) & 0xffff
    return (~crc) & 0xffff

def dnp3_frame(ctl, dst, src, th, data):
    # Link frame: 10-byte header (05 64 len ctl dst(2) src(2) crc(2)) + data
    # region. The `len` field counts the DATA bytes (the 5-byte prefix +
    # data, CRCs not included). The data region is a single 16-byte block:
    # first byte = transport header (FIR/FIN/seq), followed by up to 15
    # application bytes, then the 2-byte block CRC. Continuation frames
    # carry a new transport header byte with the incremented sequence
    # number; the last frame sets FIN.
    assert len(data) <= 15, "one frame carries th + up to 15 app bytes"
    d = bytes([th]) + data
    wire = d + dnp3_crc(d).to_bytes(2, "little")
    ln = 5 + len(d)
    hdr = bytes([0x05, 0x64, ln, ctl, dst >> 8, dst & 0xff, src >> 8, src & 0xff])
    crc = dnp3_crc(hdr)
    return hdr + bytes([crc & 0xff, crc >> 8]) + wire

class Flow:
    def __init__(self, sport, cs, ss):
        self.sp = sport
        self.cseq, self.sseq = cs + 1, ss + 1
        self.sack, self.cake = cs + 1, ss + 1
    def mk(self, src, dst, sp, dp, seq, ack, flags, payload=b""):
        p = Ether(src="00:11:22:33:44:55" if src == SIP else "66:77:88:99:aa:bb",
                  dst="66:77:88:99:aa:bb" if src == SIP else "00:11:22:33:44:55")/IP(src=src, dst=dst)/TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
        if payload: p = p/Raw(payload)
        return p
    def hs(self, pkts):
        Cs, Ss = self.cseq - 1, self.sseq - 1
        pkts.append(self.mk(SIP, DIP, self.sp, DP, Cs, 0, "S"))
        pkts.append(self.mk(DIP, SIP, DP, self.sp, Ss, Cs + 1, "SA"))
        self.c(b"", "A", pkts)
    def c(self, payload, flags, pkts):
        pkts.append(self.mk(SIP, DIP, self.sp, DP, self.cseq, self.cake, flags, payload))
        self.cseq += len(payload) + (1 if "F" in flags else 0)
        self.sack = self.cseq
    def s(self, payload, flags, pkts):
        pkts.append(self.mk(DIP, SIP, DP, self.sp, self.sseq, self.sack, flags, payload))
        self.sseq += len(payload) + (1 if "F" in flags else 0)
        self.cake = self.sseq
    def fin(self, pkts):
        self.s(b"", "F", pkts); self.c(b"", "A", pkts)
        self.c(b"", "F", pkts); self.s(b"", "A", pkts)

pkts = []

# flow A: complete two-frame message, marker split over the frames -> accepted
f = Flow(49370, 1000, 5000); f.hs(pkts)
app = b"DNP3ABORTMARK" + b"XXXXXX"
f.c(dnp3_frame(0xC4, 0x0001, 0x0002, 0x40 | 0, app[:15]), "PA", pkts); f.s(b"", "A", pkts)
f.c(dnp3_frame(0xC4, 0x0001, 0x0002, 0x80 | 1, app[15:]), "PA", pkts); f.s(b"", "A", pkts)
f.fin(pkts)

# flow B: only the first frame (FIR, no FIN), then RST -> tx stuck at
# request_started (progress 0) when the flow dies
f = Flow(49371, 2000, 6000); f.hs(pkts)
f.c(dnp3_frame(0xC4, 0x0001, 0x0002, 0x40 | 0, b"QQQQQQQQQQQQQQQ"), "PA", pkts); f.s(b"", "A", pkts)
pkts.append(f.mk(SIP, DIP, f.sp, DP, f.cseq, f.cake, "R"))

wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
