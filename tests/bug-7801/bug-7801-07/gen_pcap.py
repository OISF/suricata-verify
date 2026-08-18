#!/usr/bin/env python3
"""Generate PCAP for pipelined multi-TX false positive prevention test.

Rule: extract val from URI, then isdataat:!val,relative on stat_msg
      after matching "O" in "OK". After "O", 1 byte remains ("K").

TX1: GET /val/01/a -> 200 OK.  isdataat:!1 -> NOT 1 byte after "O"?
     After "O" there IS 1 byte ("K"), so !1 is FALSE -> no alert. CORRECT.

TX2: GET /val/08/b -> 200 OK.  isdataat:!8 -> NOT 8 bytes after "O"?
     Only 1 byte remains, so !8 is TRUE -> alert. CORRECT.

Packet order:
  Handshake
  Request 1  (byte_extract -> 1)
  Request 2  (byte_extract -> 8, clobbers det_ctx)
  Response 1 (isdataat:!??? without cache: !8 -> TRUE -> FALSE POSITIVE on TX1)
  Response 2 (isdataat:!8 -> TRUE -> alert)
  Teardown

Without TX cache: 2 alerts (TX1 false positive: sees 8 from TX2).
With TX cache:    1 alert  (TX2 only, TX1 correctly restores 1).
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC = "192.168.1.100"
DST = "192.168.1.1"
SPORT = 40011
DPORT = 80

req1 = (
    b"GET /val/01/a HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
req2 = (
    b"GET /val/08/b HTTP/1.1\r\n"
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

# Request 1 (TX1 — extracts 1, should NOT alert)
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c_seq, ack=s_seq) / Raw(load=req1))
c_seq += len(req1)

# Request 2 (TX2 — extracts 8, should alert, clobbers det_ctx)
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
print("Generated input.pcap: pipelined multi-TX false positive prevention, expect 1 alert with TX cache")
