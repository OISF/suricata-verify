#!/usr/bin/env python3

# DCERPC bind and bind_ack over TCP on a port without a probing parser,
# with the first segment of the bind_ack, then of the bind, shorter than
# the 16 bytes of the DCERPC header.

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"
MAC = {CLIENT: "00:00:00:00:00:01", SERVER: "00:00:00:00:00:02"}
PORT = 49999

# endpoint mapper interface and NDR transfer syntax
EPM = bytes.fromhex("0883afe11f5dc91191a408002b14a0fa03000000")
NDR = bytes.fromhex("045d888aeb1cc9119fe808002b10486002000000")

BIND = (
    bytes.fromhex("05000b03100000004800000001000000")
    + bytes.fromhex("b810b81000000000")
    + bytes.fromhex("01000000")
    + bytes.fromhex("00000100")
    + EPM
    + NDR
)
BIND_ACK = (
    bytes.fromhex("05000c03100000003c00000001000000")
    + bytes.fromhex("b810b81045230000")
    + bytes.fromhex("0400")
    + b"135\x00"
    + b"\x00\x00"
    + bytes.fromhex("01000000")
    + bytes.fromhex("00000000")
    + NDR
)

packets = []


def pkt(src, dst, sport, dport, flags, seq, ack, data=b""):
    return (
        Ether(src=MAC[src], dst=MAC[dst])
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        / data
    )


def session(sport, request_segments, response_segments):
    cseq, sseq = 1000, 5000
    packets.append(pkt(CLIENT, SERVER, sport, PORT, "S", cseq, 0))
    packets.append(pkt(SERVER, CLIENT, PORT, sport, "SA", sseq, cseq + 1))
    cseq += 1
    sseq += 1
    packets.append(pkt(CLIENT, SERVER, sport, PORT, "A", cseq, sseq))
    for seg in request_segments:
        packets.append(pkt(CLIENT, SERVER, sport, PORT, "PA", cseq, sseq, seg))
        cseq += len(seg)
        packets.append(pkt(SERVER, CLIENT, PORT, sport, "A", sseq, cseq))
    for seg in response_segments:
        packets.append(pkt(SERVER, CLIENT, PORT, sport, "PA", sseq, cseq, seg))
        sseq += len(seg)
        packets.append(pkt(CLIENT, SERVER, sport, PORT, "A", cseq, sseq))


session(40001, [BIND], [BIND_ACK[:12], BIND_ACK[12:]])
session(40002, [BIND[:12], BIND[12:]], [BIND_ACK])

wrpcap("input.pcap", packets)
