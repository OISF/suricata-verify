#!/usr/bin/env python3
# One HTTP/1.1 flow in two segments: the request line and the Host header go out
# in the first segment, so the transaction reaches the request_headers progress
# with a header buffer that can still grow. The second segment adds a header no
# rule looks for, which is what makes the pending rule of the test pending.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "142.251.111.105"
SP, DP = 49152, 80
SMAC, DMAC = "00:11:22:33:44:55", "66:77:88:99:aa:bb"

cseq, sseq, cake = 1, 1, 1
pkts = []

def mk(src, dst, sp, dp, seq, ack, flags, payload=None):
    sm, dm = (SMAC, DMAC) if src == SIP else (DMAC, SMAC)
    p = Ether(src=sm, dst=dm) / IP(src=src, dst=dst) / TCP(
        sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
    if payload:
        p = p / Raw(load=payload)
    pkts.append(p)
    return p

# handshake
mk(SIP, DIP, SP, DP, cseq, sseq, "S"); cseq += 1; sseq += 1
mk(DIP, SIP, DP, SP, sseq, cseq, "SA"); sseq += 1
mk(SIP, DIP, SP, DP, cseq, sseq, "A"); cake = sseq

def cs(payload):
    global cseq, cake
    mk(SIP, DIP, SP, DP, cseq, cake, "PA", payload)
    cseq += len(payload or b"")
    mk(DIP, SIP, DP, SP, sseq, cseq, "A"); cake = cseq

def ss(payload):
    global sseq, cake
    mk(DIP, SIP, DP, SP, sseq, cake, "PA", payload)
    sseq += len(payload or b"")
    mk(SIP, DIP, SP, DP, cseq, sseq, "A"); cake = sseq

cs(b"POST /index HTTP/1.1\r\nHost: www.example.com\r\n")
cs(b"X-Other: v1\r\nContent-Length: 4\r\n\r\nBODY")
ss(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
mk(SIP, DIP, SP, DP, cseq, sseq, "FA"); cseq += 1
mk(DIP, SIP, DP, SP, sseq, cseq, "FA"); sseq += 1
mk(SIP, DIP, SP, DP, cseq, sseq, "A")

wrpcap("input.pcap", pkts)
