#!/usr/bin/env python3
"""Generate PCAP for pipelined multi-TX byte_math cross-buffer cache test.

Rule: extract base from URI, byte_math computes total = second_val + base,
      then byte_test:1,>,total,0,relative on stat_code after matching "2".
      Next byte '0' = 0x30 = 48.

TX1: GET /calc/03/02 -> base=3, total = 2 + 3 = 5.
     byte_test: 48 > 5  -> TRUE  -> alert

TX2: GET /calc/40/30 -> base=40, total = 30 + 40 = 70.
     byte_test: 48 > 70 -> FALSE -> no alert (spoiler)

Packet order:
  Handshake
  Request 1  (base=3, total=5)
  Request 2  (base=40, total=70, clobbers both byte_values[0] and [1])
  Response 1 (byte_test: 48 > ??? needs TX cache for total=5)
  Response 2 (byte_test: 48 > 70 -> no alert anyway)
  Teardown

Without TX cache: 0 alerts (TX1 sees total=70 from TX2, 48 > 70 is FALSE).
With TX cache:    1 alert  (TX1 restores total=5, 48 > 5 is TRUE).
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC = "192.168.1.100"
DST = "192.168.1.1"
SPORT = 40012
DPORT = 80

req1 = (
    b"GET /calc/03/02 HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
req2 = (
    b"GET /calc/40/30 HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
resp1 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 2\r\n"
    b"\r\n"
    b"OK"
)
resp2 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 2\r\n"
    b"\r\n"
    b"OK"
)

c_seq = 100
s_seq = 200

pkts = []

# Handshake
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="S", seq=c_seq))
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="SA", seq=s_seq, ack=c_seq + 1))
c_seq += 1
s_seq += 1
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c_seq, ack=s_seq))

# Request 1 (TX1 — base=3, total=5)
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c_seq, ack=s_seq) / Raw(load=req1))
c_seq += len(req1)

# Request 2 (TX2 — base=40, total=70, clobbers det_ctx)
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c_seq, ack=s_seq) / Raw(load=req2))
c_seq += len(req2)

# ACK from server
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="A", seq=s_seq, ack=c_seq))

# Response 1 (TX1)
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA", seq=s_seq, ack=c_seq) / Raw(load=resp1))
s_seq += len(resp1)

# Response 2 (TX2)
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA", seq=s_seq, ack=c_seq) / Raw(load=resp2))
s_seq += len(resp2)

# Teardown
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="FA", seq=c_seq, ack=s_seq))
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="FA", seq=s_seq, ack=c_seq + 1))
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c_seq + 1, ack=s_seq + 1))

wrpcap("input.pcap", pkts)
print("Generated input.pcap: pipelined multi-TX byte_math, expect 1 alert with TX cache")
