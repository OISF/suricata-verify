#!/usr/bin/env python3
"""Generate test.pcap. 43 packets, 30.04 s of packet time.

Two tuples:
- A (10.0.0.2:45010): a connection at t=0 with no FIN, then silence, then a
  second connection on the same tuple at t=30.
- B (10.0.0.3:45020): one connection that sends a packet every second until
  t=29.6, which is what moves the packet clock forward.

With 4 workers, tuple A and tuple B land on at most two of them, so at least two
workers never see a packet. Offline time is the oldest packet timestamp of the
workers: measured against host time those workers hold the clock at t=0 for the
whole run, measured in packet time they are ignored and the clock follows B. The
events of the run are stamped with that clock, which is what the test checks.

Keep B moving for more than the 5 s staleness window, else the idle workers are
not stale in packet time either and the two agree.
"""

import scapy.all as scapy

OUT = "test.pcap"
SRV = "192.168.1.10"
T0 = 1700000000.0
A_HOST, A_PORT = "10.0.0.2", 45010
B_HOST, B_PORT = "10.0.0.3", 45020

pkts = []


def add(src, dst, sp, dp, flags, seq, ack, payload, when):
    p = scapy.IP(src=src, dst=dst) / scapy.TCP(
        sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
    if payload:
        p = p / scapy.Raw(load=payload)
    p.time = when
    pkts.append(p)


def handshake(host, port, cseq, tag, when, fin=False):
    sseq = cseq + 50000
    add(host, SRV, port, 80, "S", cseq, sseq, None, when)
    add(SRV, host, 80, port, "SA", sseq, cseq + 1, None, when + 0.01)
    add(host, SRV, port, 80, "A", cseq + 1, sseq + 1, None, when + 0.02)
    add(host, SRV, port, 80, "PA", cseq + 1, sseq + 1, tag, when + 0.03)
    if fin:
        add(host, SRV, port, 80, "FA", cseq + 1 + len(tag), sseq + 1, None, when + 0.04)


# A: connection without FIN, so nothing closes it before the file ends
handshake(A_HOST, A_PORT, 1000, b"A-REQ-1", T0)
# B: keeps the packet clock moving
handshake(B_HOST, B_PORT, 5000, b"B-START", T0 + 0.5)
for sec in range(0, 30):
    # B-START is 7 bytes at seq 5001, so the stream continues at 5008; each keep
    # alive is 6 bytes and must land flush on the end of the previous one, else
    # the stream has holes (or overlaps the first one).
    add(B_HOST, SRV, B_PORT, 80, "PA", 5008 + 6 * sec, 55001, b"B-KEEP", T0 + sec + 0.6)
# A again on the same tuple, 30 s later
handshake(A_HOST, A_PORT, 90000, b"A-REQ-2", T0 + 30, fin=True)

pkts.sort(key=lambda p: p.time)
scapy.wrpcap(OUT, pkts)
print("%d packets, %.2f s of packet time" % (len(pkts), pkts[-1].time - pkts[0].time))
