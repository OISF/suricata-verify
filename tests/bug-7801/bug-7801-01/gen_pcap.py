#!/usr/bin/env python3
"""Generate PCAP for bidirectional cross-buffer byte_extract test.

Test: Extract from http.uri (toserver) -> byte_test in http.stat_code (toclient).

TX1: GET /data/05/ -> 200 OK.  byte_extract "05" = 5.
     stat_code "200", after "2": byte '0' = 0x30 = 48.  byte_test: 48 > 5 -> alert.

TX2: GET /data/99/ -> 200 OK.  byte_extract "99" = 99.  (spoiler)
     byte_test: 48 > 99 -> FALSE -> no alert.

Pipelined: both requests sent before any response.
TX2's byte_extract clobbers det_ctx->byte_values[0] = 99 before TX1's
toclient inspection.

Without TX cache: 0 alerts (TX1 sees 99, 48 > 99 is FALSE).
With TX cache:    1 alert  (TX1 restores 5, 48 > 5 is TRUE).
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC = "192.168.1.100"
DST = "192.168.1.1"
SPORT = 40001
DPORT = 80

req1 = (
    b"GET /data/05/index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
req2 = (
    b"GET /data/99/index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
resp1 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 4\r\n"
    b"\r\n"
    b"test"
)
resp2 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 4\r\n"
    b"\r\n"
    b"test"
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
print("Generated input.pcap for bidirectional URI(toserver) -> stat_code(toclient) test")
