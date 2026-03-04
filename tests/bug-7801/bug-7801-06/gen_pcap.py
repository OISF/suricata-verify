#!/usr/bin/env python3
"""Generate PCAP for pipelined HTTP/1.1 multi-TX byte cache test.

Single TCP connection with two pipelined HTTP requests followed by two
responses.  TX2's byte_extract clobbers det_ctx->byte_values[0] before
TX1's response (consumer) is inspected.

Rule: extract val from URI, then byte_test:1,>,val,0,relative on stat_code
      after matching "2" in "200". Next byte '0' = 0x30 = 48.

TX1: GET /val/05/a -> 200 OK.  byte_test: 48 > 5  -> TRUE  -> alert
TX2: GET /val/99/b -> 200 OK.  byte_test: 48 > 99 -> FALSE -> no alert
     (TX2 is the spoiler — its extraction clobbers det_ctx)

Packet order:
  Handshake
  Request 1  (byte_extract -> 5)
  Request 2  (byte_extract -> 99, clobbers det_ctx)
  Response 1 (byte_test: 48 > ??? needs TX cache for 5)
  Response 2 (byte_test: 48 > 99 -> no alert anyway)
  Teardown

Without TX cache: 0 alerts (TX1 sees 99 from TX2).
With TX cache:    1 alert  (TX1 restores 5 from cache).
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC = "192.168.1.100"
DST = "192.168.1.1"
SPORT = 40010
DPORT = 80

req1 = (
    b"GET /val/05/a HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
req2 = (
    b"GET /val/99/b HTTP/1.1\r\n"
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

# Request 1 (TX1)
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c_seq, ack=s_seq) / Raw(load=req1))
c_seq += len(req1)

# Request 2 (TX2) — pipelined before any response
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c_seq, ack=s_seq) / Raw(load=req2))
c_seq += len(req2)

# ACK from server for both requests
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
print("Generated input.pcap: pipelined multi-TX, expect 1 alert with TX cache")
