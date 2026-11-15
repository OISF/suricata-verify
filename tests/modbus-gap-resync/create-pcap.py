#!/usr/bin/env python3
"""Modbus/TCP flows with TCP gaps, for the gap recovery of the Modbus parser.

Each flow carries four Read Coils request/response pairs
(transaction ids 1-4). One segment is never seen by the engine (it is acked,
so the stream engine reports a gap):

  port 40001  request 2 and its response are lost
  port 40002  only response 2 is lost
  port 40003  the first half of request 2 is lost, its tail arrives
"""

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"


def req(tid):
    # Read Coils, 8 coils from address tid
    return bytes([tid >> 8, tid & 0xFF, 0, 0, 0, 6, 1, 1, 0, tid, 0, 8])


def rsp(tid):
    # one byte of coil status
    return bytes([tid >> 8, tid & 0xFF, 0, 0, 0, 4, 1, 1, 1, tid])


def flow(sport, case, t0):
    pkts = []
    cs, ss = 1000, 5000

    def c2s(flags, payload=b"", seq=None, lost=False):
        nonlocal cs
        p = (
            Ether()
            / IP(src=CLIENT, dst=SERVER)
            / TCP(sport=sport, dport=502, flags=flags, seq=cs if seq is None else seq, ack=ss)
        )
        if payload:
            p = p / Raw(payload)
        if not lost:
            pkts.append(p)
        cs += len(payload) + (1 if flags in ("S", "FA") else 0)

    def s2c(flags, payload=b"", lost=False):
        nonlocal ss
        p = (
            Ether()
            / IP(src=SERVER, dst=CLIENT)
            / TCP(sport=502, dport=sport, flags=flags, seq=ss, ack=cs)
        )
        if payload:
            p = p / Raw(payload)
        if not lost:
            pkts.append(p)
        ss += len(payload) + (1 if flags in ("SA", "FA") else 0)

    c2s("S")
    s2c("SA")
    c2s("A")
    for tid in range(1, 5):
        r = req(tid)
        if tid == 2 and case == "split":
            c2s("PA", r[:5], lost=True)
            c2s("PA", r[5:])
        else:
            c2s("PA", r, lost=(tid == 2 and case == "both"))
        s2c("PA", rsp(tid), lost=(tid == 2 and case in ("both", "response")))
        c2s("A")
    c2s("FA")
    s2c("FA")
    c2s("A")
    for i, p in enumerate(pkts):
        p.time = t0 + i * 0.01
    return pkts


pkts = []
for i, (port, case) in enumerate(((40001, "both"), (40002, "response"), (40003, "split"))):
    pkts += flow(port, case, 1 + i * 10)
wrpcap("input.pcap", pkts)
