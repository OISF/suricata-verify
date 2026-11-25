#!/usr/bin/env python3
"""Generate PCAP for two byte variables produced in different buffers.

One rule, one transaction, two producers of different kinds:

  http.uri        byte_extract -> uri_val  = 42
  http.stat_code  byte_math    -> code_val = 200 + 1
  file.data       byte_test: "42" == uri_val

byte_extract and byte_math take their local_id from one counter per
signature, so uri_val and code_val occupy different slots. When each keyword
type counted its own, the first byte_extract and the first byte_math in a rule
both got slot 0: code_val overwrote uri_val before the file.data consumer ran,
byte_test compared 42 against 201 and the rule did not fire.

Single connection, no pipelining and no spoiler transaction - the two
producers in the same rule are the whole test.

With a shared slot:    0 alerts.
With distinct slots:   1 alert.
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC = "192.168.1.100"
DST = "192.168.1.1"
SPORT = 40015
DPORT = 80

req = (
    b"GET /a/42/index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)
resp = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 3\r\n"
    b"\r\n"
    b"x42"
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

# Request: http.uri producer, uri_val = 42
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c_seq, ack=s_seq) / Raw(load=req))
c_seq += len(req)
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="A", seq=s_seq, ack=c_seq))

# Response: http.stat_code producer (code_val = 200), then file.data consumer
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA", seq=s_seq, ack=c_seq) / Raw(load=resp))
s_seq += len(resp)
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c_seq, ack=s_seq))

# Teardown
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="FA", seq=c_seq, ack=s_seq))
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="FA", seq=s_seq, ack=c_seq + 1))
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c_seq + 1, ack=s_seq + 1))

wrpcap("input.pcap", pkts)
print("Generated input.pcap: two producers in different buffers, expect 1 alert")
