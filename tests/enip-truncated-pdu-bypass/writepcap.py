#!/usr/bin/env python3
# ENIP over TCP: an ENIP PDU whose body spans two TCP segments must be
# reassembled, not dropped.
#
# Each ENIP PDU is a 24-byte header (which carries the body length, "pdulen")
# followed by that many body bytes. When a header arrives in one TCP segment but
# its body only arrives in a later segment, EnipState::parse_tcp() must return
# AppLayerResult::incomplete() and wait for the rest, then parse the reassembled
# PDU. (Previously take(pdulen) on the short slice returned nom::Err::Error, so
# parse_tcp() returned AppLayerResult::err() and app-layer parsing was disabled
# for the whole flow -- the PDU and everything after it went uninspected.)
#
# Two flows carry the *same* two ENIP PDUs:
#   * a ListIdentity request (cmd 0x0063, empty body), and
#   * a SendRRData request (cmd 0x006f) carrying an unconnected CIP
#     Get_Attribute_List (service 0x03) on class 0x8b.
#
#   flow 1 (client port 40001) - CONTIGUOUS: both PDUs in a single 74-byte
#     segment.
#   flow 2 (client port 40002) - SPLIT: first segment holds ListIdentity plus
#     only the 24-byte SendRRData header; the SendRRData body arrives in a second
#     segment, so the PDU is reassembled across two segments.
#
# Both flows must yield identical inspection results: the CIP request is decoded
# and both Wireshark and Suricata recognise it.

import struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SRV, CLI, DPORT = "10.0.0.1", "10.0.0.2", 44818
CMAC, SMAC = "00:11:22:33:44:55", "66:77:88:99:aa:bb"


def enip_header(cmd, pdulen):
    # cmd, pdulen, session, status, context(8), options -> 24 bytes
    return struct.pack("<HHIIQI", cmd, pdulen, 0, 0, 0, 0)


# PDU #1: ListIdentity request, empty body.
PDU1 = enip_header(0x0063, 0)
assert len(PDU1) == 24

# PDU #2: SendRRData carrying an unconnected CIP Get_Attribute_List request.
CIP = bytes.fromhex("0302208b240101000800")     # svc 0x03, path class 0x8b/inst 1, data
SENDRR_BODY = (
    struct.pack("<I", 0)          # interface handle (CIP)
    + struct.pack("<H", 0)        # timeout
    + struct.pack("<H", 2)        # CPF item count
    + struct.pack("<HH", 0x0000, 0)            # Null Address Item
    + struct.pack("<HH", 0x00b2, len(CIP)) + CIP  # Unconnected Data Item + CIP
)
PDU2_HDR = enip_header(0x006f, len(SENDRR_BODY))
PDU2 = PDU2_HDR + SENDRR_BODY
assert len(PDU2_HDR) == 24


def eth(src, dst):
    return Ether(src=src, dst=dst)


def handshake(sport, cseq, sseq):
    return [
        eth(CMAC, SMAC) / IP(src=CLI, dst=SRV) / TCP(sport=sport, dport=DPORT, flags="S", seq=cseq),
        eth(SMAC, CMAC) / IP(src=SRV, dst=CLI) / TCP(sport=DPORT, dport=sport, flags="SA", seq=sseq, ack=cseq + 1),
        eth(CMAC, SMAC) / IP(src=CLI, dst=SRV) / TCP(sport=sport, dport=DPORT, flags="A", seq=cseq + 1, ack=sseq + 1),
    ]


def cseg(sport, seq, ack, payload):
    return eth(CMAC, SMAC) / IP(src=CLI, dst=SRV) / \
        TCP(sport=sport, dport=DPORT, flags="PA", seq=seq, ack=ack) / Raw(load=payload)


def sack(sport, seq, ack):
    return eth(SMAC, CMAC) / IP(src=SRV, dst=CLI) / TCP(sport=DPORT, dport=sport, flags="A", seq=seq, ack=ack)


pkts = []

# ---- Flow 1: CONTIGUOUS (client port 40001) ----
sp, cseq, sseq = 40001, 1000, 5000
pkts += handshake(sp, cseq, sseq)
c = cseq + 1
pkts += [cseg(sp, c, sseq + 1, PDU1 + PDU2)]      # both PDUs in one segment
c += len(PDU1 + PDU2)
pkts += [sack(sp, sseq + 1, c)]

# ---- Flow 2: SPLIT / reassembled (client port 40002) ----
sp, cseq, sseq = 40002, 2000, 6000
pkts += handshake(sp, cseq, sseq)
c = cseq + 1
pkts += [cseg(sp, c, sseq + 1, PDU1 + PDU2_HDR)]  # ListIdentity + SendRRData header only
c += len(PDU1 + PDU2_HDR)
pkts += [sack(sp, sseq + 1, c)]
pkts += [cseg(sp, c, sseq + 1, SENDRR_BODY)]      # SendRRData body arrives now
c += len(SENDRR_BODY)
pkts += [sack(sp, sseq + 1, c)]

wrpcap("input.pcap", pkts)
print("wrote %d packets; PDU1=%dB PDU2=%dB (hdr %dB + body %dB)" %
      (len(pkts), len(PDU1), len(PDU2), len(PDU2_HDR), len(SENDRR_BODY)))
