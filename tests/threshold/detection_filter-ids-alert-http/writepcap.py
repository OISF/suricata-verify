#!/usr/bin/env python3
# One keep-alive HTTP/1.1 flow with 6 "GET /df" request/response pairs,
# each segment ACKed, then FIN teardown.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

C, S = "10.0.0.1", "10.0.0.2"
CP, SP = 40002, 80
eth_c = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
eth_s = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")

pkts = []
cseq, sseq = 1000, 5000

pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="S", seq=cseq))
pkts.append(eth_s / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags="SA", seq=sseq, ack=cseq + 1))
cseq += 1
sseq += 1
pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="A", seq=cseq, ack=sseq))

body = b"ok\n"
resp = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)

for i in range(1, 7):
    req = b"GET /df?n=%d HTTP/1.1\r\nHost: example.test\r\n\r\n" % i
    pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="PA", seq=cseq, ack=sseq) / Raw(req))
    cseq += len(req)
    pkts.append(eth_s / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags="A", seq=sseq, ack=cseq))
    pkts.append(eth_s / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags="PA", seq=sseq, ack=cseq) / Raw(resp))
    sseq += len(resp)
    pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="A", seq=cseq, ack=sseq))

pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="FA", seq=cseq, ack=sseq))
pkts.append(eth_s / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags="FA", seq=sseq, ack=cseq + 1))
pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="A", seq=cseq + 1, ack=sseq + 1))

for n, p in enumerate(pkts):
    p.time = 1700000000 + n * 0.01

wrpcap("input.pcap", pkts)
