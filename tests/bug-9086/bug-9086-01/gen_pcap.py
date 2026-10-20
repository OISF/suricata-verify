#!/usr/bin/env python3
"""Generate PCAP for bug 9086: isdataat reading a variable whose local id is 1.

One request, GET /v/1/5/ENDxx. Rule 1 extracts a = 1 (local id 0) and b = 5
(local id 1) from the URI, matches "END" and asks isdataat:!b,relative: two
bytes follow "END", fewer than 5, so it alerts. Rule 2 is the literal form,
isdataat:!1,relative, which Suricata rewrites into "END" with endswith; the URI
does not end there, so it must not alert.

The rewrite tested the stored number for 1 without asking whether it was a byte
count or a variable's local id. Rule 1 was rewritten like rule 2 and lost its
length check: 0 alerts.
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC, DST, SPORT, DPORT = "192.168.1.100", "192.168.1.1", 40026, 80
req = b"GET /v/1/5/ENDxx HTTP/1.1\r\nHost: example.com\r\n\r\n"
resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

c, s = 100, 200
pkts = [IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="S", seq=c),
        IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="SA", seq=s, ack=c + 1)]
c += 1
s += 1
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c, ack=s))
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c, ack=s) / Raw(load=req))
c += len(req)
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="A", seq=s, ack=c))
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA", seq=s, ack=c) / Raw(load=resp))
s += len(resp)
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c, ack=s))
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="FA", seq=c, ack=s))
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="FA", seq=s, ack=c + 1))
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c + 1, ack=s + 1))
wrpcap("input.pcap", pkts)
