#!/usr/bin/env python3
"""Generate PCAP for multi-pass toclient restore byte cache test.

Rule: byte_extract from http.uri (toserver), then match http.stat_code AND
file.data (toclient).  Because http.stat_code (RESPONSE_LINE progress) and
file.data (RESPONSE_BODY progress) are separate inspect engines, the detect
engine makes two separate toclient inspection passes per TX, calling restore
twice for each TX.

With a pointer-swap restore, the second restore for TX1 picks up the wrong
buffer (the scratch buffer that was left by TX2's first restore), reading
zero instead of the extracted value. This means the byte_test fails for TX1.

Both TXs should alert (count: 2):

TX1: GET /data/11/ -> 200 OK, body "test22".
     byte_extract "11" = 11. file.data: string read after "test" gives "22" = 22.
     byte_test: 22 > 11 -> TRUE -> alert.

TX2: GET /data/88/ -> 200 OK, body "test99".
     byte_extract "88" = 88. file.data: string read after "test" gives "99" = 99.
     byte_test: 99 > 88 -> TRUE -> alert.

Packet order:
  Handshake
  Request 1  (TX1, byte_extract -> 11)
  Request 2  (TX2, byte_extract -> 88)
  Server ACK
  Response 1 headers + body + Response 2 response line  (single packet)
  Response 2 headers + body                             (second packet)
  Teardown

In the first response packet, the detect engine runs stat_code and file.data
for TX1 AND stat_code for TX2 (TX2 body not yet available).  With a swap-based
restore this corrupts the per-TX state for both TXs before the file.data pass.
With a memcpy-based restore each TX's state buffer is stable and both alert.

Without TX cache (swap): 0 alerts.
With TX cache (memcpy):  2 alerts.
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC = "192.168.1.100"
DST = "192.168.1.1"
SPORT = 40001
DPORT = 80

req1 = (
    b"GET /data/11/index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
req2 = (
    b"GET /data/88/index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
resp1 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 6\r\n"
    b"\r\n"
    b"test22"
    b"HTTP/1.1 200 OK\r\n"
)
resp2 = (
    b"Content-Type: text/html\r\n"
    b"Content-Length: 6\r\n"
    b"\r\n"
    b"test99"
)

c_seq = 100
s_seq = 200
pkts = []

# Handshake
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="S", seq=c_seq))
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="SA", seq=s_seq, ack=c_seq + 1))
c_seq += 1; s_seq += 1
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c_seq, ack=s_seq))

# Pipelined requests
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c_seq, ack=s_seq) / Raw(load=req1))
c_seq += len(req1)
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c_seq, ack=s_seq) / Raw(load=req2))
c_seq += len(req2)

# Server ACK
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="A", seq=s_seq, ack=c_seq))

# Responses
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA", seq=s_seq, ack=c_seq) / Raw(load=resp1))
s_seq += len(resp1)
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA", seq=s_seq, ack=c_seq) / Raw(load=resp2))
s_seq += len(resp2)

# Teardown
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="FA", seq=c_seq, ack=s_seq))
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="FA", seq=s_seq, ack=c_seq + 1))
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c_seq + 1, ack=s_seq + 1))

wrpcap("input.pcap", pkts)
print("Generated input.pcap: multi-pass toclient restore test, expect 2 alerts with TX cache")
