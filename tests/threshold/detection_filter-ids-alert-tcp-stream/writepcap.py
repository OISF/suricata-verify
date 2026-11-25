#!/usr/bin/env python3
# One TCP flow: handshake, 6 client data segments carrying "DFMATCH",
# each ACKed by the server, then FIN teardown.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

C, S = "10.0.0.1", "10.0.0.2"
CP, SP = 40000, 9999
eth_c = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
eth_s = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")

pkts = []
cseq, sseq = 1000, 5000

pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="S", seq=cseq))
pkts.append(eth_s / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags="SA", seq=sseq, ack=cseq + 1))
cseq += 1
sseq += 1
pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="A", seq=cseq, ack=sseq))

for i in range(1, 7):
    payload = b"DFMATCH%d\n" % i
    pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="PA", seq=cseq, ack=sseq) / Raw(payload))
    cseq += len(payload)
    pkts.append(eth_s / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags="A", seq=sseq, ack=cseq))

pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="FA", seq=cseq, ack=sseq))
pkts.append(eth_s / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags="FA", seq=sseq, ack=cseq + 1))
pkts.append(eth_c / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags="A", seq=cseq + 1, ack=sseq + 1))

for n, p in enumerate(pkts):
    p.time = 1700000000 + n * 0.01

wrpcap("input.pcap", pkts)
