#!/usr/bin/env python3
#
# Generate a TCP flow where only the toclient direction exceeds the
# rate-tracking threshold (10KiB per 10s in the test config).
#
# Client sends one small request, server sends ~70KB back. Client ACKs are
# header only, so the toserver direction stays well below 10KiB.

from scapy.all import IP, TCP, Ether, Raw, wrpcap

cli, srv = "10.0.0.1", "10.0.0.2"
sport, dport = 40000, 8080
cmac, smac = "00:00:00:00:00:01", "00:00:00:00:00:02"

pkts = []
t = 1700000000.0


def c2s(flags, seq, ack, payload=b""):
    p = Ether(src=cmac, dst=smac) / IP(src=cli, dst=srv) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    return p / Raw(payload) if payload else p


def s2c(flags, seq, ack, payload=b""):
    p = Ether(src=smac, dst=cmac) / IP(src=srv, dst=cli) / TCP(
        sport=dport, dport=sport, flags=flags, seq=seq, ack=ack)
    return p / Raw(payload) if payload else p


def add(p):
    global t
    t += 0.001
    p.time = t
    pkts.append(p)


cseq, sseq = 1000, 5000
add(c2s("S", cseq, 0))
add(s2c("SA", sseq, cseq + 1))
cseq += 1
sseq += 1
add(c2s("A", cseq, sseq))

req = b"GET /big HTTP/1.0\r\n\r\n"
add(c2s("PA", cseq, sseq, req))
cseq += len(req)

seg = b"A" * 1400
for _ in range(50):
    add(s2c("A", sseq, cseq, seg))
    sseq += len(seg)
    add(c2s("A", cseq, sseq))

add(s2c("FA", sseq, cseq))
sseq += 1
add(c2s("FA", cseq, sseq))
cseq += 1
add(s2c("A", sseq, cseq))

wrpcap("input.pcap", pkts)
