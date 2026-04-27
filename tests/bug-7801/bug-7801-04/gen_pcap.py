#!/usr/bin/env python3
"""Generate PCAP for bidirectional cross-buffer byte_extract + byte_math test.

Test: Extract from http.uri (toserver), compute with byte_math, then use
result via isdataat in http.stat_msg (toclient).

TX1: URI "/math/03/02":
  byte_extract "03" = 3 (a_val), byte_math reads "02" = 2, sum_val = 2 + 3 = 5.
  stat_msg "OK", after "O": 1 byte remains.
  isdataat:!5,relative -> NOT 5 bytes? TRUE -> alert.

TX2: URI "/math/01/00":  (spoiler)
  byte_extract "01" = 1 (a_val), byte_math reads "00" = 0, sum_val = 0 + 1 = 1.
  isdataat:!1,relative -> NOT 1 byte? FALSE (exactly 1 remains) -> no alert.

Pipelined: both requests sent before any response.
TX2's byte_extract/byte_math clobber byte_values[0]=1 and byte_values[1]=1
before TX1's toclient inspection.

Without TX cache: 0 alerts (TX1 sees sum_val=1, isdataat:!1 is FALSE).
With TX cache:    1 alert  (TX1 restores sum_val=5, isdataat:!5 is TRUE).
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC = "192.168.1.100"
DST = "192.168.1.1"
SPORT = 40004
DPORT = 80

req1 = (
    b"GET /math/03/02 HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
req2 = (
    b"GET /math/01/00 HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
resp1 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 4\r\n"
    b"\r\n"
    b"done"
)
resp2 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 4\r\n"
    b"\r\n"
    b"done"
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
print("Generated input.pcap for bidirectional byte_extract + byte_math uri(toserver) -> stat_msg(toclient) test")
