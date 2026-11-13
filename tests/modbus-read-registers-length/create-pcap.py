#!/usr/bin/env python3
"""One Modbus/TCP flow with read requests and their responses, for the length
check that pairs a read response with its request.

  tid 1  Read Holding Registers, 11 registers, 22 data octets   (correct)
  tid 2  Read Input Registers, 2 registers, 4 data octets        (correct)
  tid 3  Read Coils, 11 coils, 2 data octets                     (correct)
  tid 4  Read Holding Registers, 2 registers, 2 data octets      (one short)
"""

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"

# (transaction id, function code, quantity, data octets in the response)
READS = ((1, 3, 11, 22), (2, 4, 2, 4), (3, 1, 11, 2), (4, 3, 2, 2))


def mbap(tid, pdu):
    return bytes([tid >> 8, tid & 0xFF, 0, 0, (len(pdu) + 1) >> 8, (len(pdu) + 1) & 0xFF, 1]) + pdu


def req(tid, fc, quantity):
    return mbap(tid, bytes([fc, 0, 0, quantity >> 8, quantity & 0xFF]))


def rsp(tid, fc, count):
    return mbap(tid, bytes([fc, count]) + bytes(range(1, count + 1)))


pkts = []
cs, ss = 1000, 5000


def c2s(flags, payload=b""):
    global cs
    p = Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=40000, dport=502, flags=flags, seq=cs, ack=ss)
    pkts.append(p / Raw(payload) if payload else p)
    cs += len(payload) + (1 if flags in ("S", "FA") else 0)


def s2c(flags, payload=b""):
    global ss
    p = Ether() / IP(src=SERVER, dst=CLIENT) / TCP(sport=502, dport=40000, flags=flags, seq=ss, ack=cs)
    pkts.append(p / Raw(payload) if payload else p)
    ss += len(payload) + (1 if flags in ("SA", "FA") else 0)


c2s("S")
s2c("SA")
c2s("A")
for tid, fc, quantity, count in READS:
    c2s("PA", req(tid, fc, quantity))
    s2c("PA", rsp(tid, fc, count))
    c2s("A")
c2s("FA")
s2c("FA")
c2s("A")
for i, p in enumerate(pkts):
    p.time = 1 + i * 0.01
wrpcap("input.pcap", pkts)
