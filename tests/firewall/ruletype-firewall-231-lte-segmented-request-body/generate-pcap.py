#!/usr/bin/env python3
# Generates input.pcap: an HTTP POST whose body is split over two TCP segments.
# The keyword content ("second") only appears in the SECOND segment.
#
#   head  : POST /submit, Content-Length: 34
#   seg1  : 20 x "A"                       (no keyword)
#   seg2  : "second" + 8 x "B"             (keyword present)
#   rsp   : 200 OK
#
# Flow: 10.20.0.14 -> 142.251.111.105 ($HOME_NET -> $EXTERNAL_NET).
# HTTP POST with a segmented body (2 segments); "second" only in the second segment.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "142.251.111.105"
SP, DP = 49152, 80

head = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 34\r\n\r\n"
seg1 = b"A" * 20
seg2 = b"second" + b"B" * 8          # 14 bytes; 20 + 14 = 34
rsp  = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"

Cs, Ss = 1000, 5000
cseq = Cs + 1
sseq = Ss + 1
sack = Cs + 1
cake = Ss + 1
pkts = []

def mk(src, dst, sp, dp, seq, ack, flags, payload=b""):
    p = Ether(src="00:11:22:33:44:55" if src == SIP else "66:77:88:99:aa:bb",
              dst="66:77:88:99:aa:bb" if src == SIP else "00:11:22:33:44:55")/IP(src=src, dst=dst)/TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
    if payload: p = p/Raw(payload)
    return p

def c(payload, flags="PA"):
    global cseq, sack
    pkts.append(mk(SIP, DIP, SP, DP, cseq, cake, flags, payload))
    cseq += len(payload) + (1 if "F" in flags else 0)
    sack = cseq

def s(payload, flags="PA"):
    global sseq, cake
    pkts.append(mk(DIP, SIP, DP, SP, sseq, sack, flags, payload))
    sseq += len(payload) + (1 if "F" in flags else 0)
    cake = sseq

pkts.append(mk(SIP, DIP, SP, DP, Cs, 0, "S"))
pkts.append(mk(DIP, SIP, DP, SP, Ss, Cs + 1, "SA"))
c(b"", "A")
c(head); s(b"", "A")
c(seg1);  s(b"", "A")
c(seg2);  s(b"", "A")
s(rsp)
s(b"", "F"); c(b"", "A")
c(b"", "F"); s(b"", "A")
wrpcap("input.pcap", pkts)
print("wrote input.pcap", len(pkts), "packets")
