#!/usr/bin/env python3

# Two valid SIP requests with many headers sent one byte per segment.

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"
MAC = {CLIENT: "00:00:00:00:00:01", SERVER: "00:00:00:00:00:02"}

packets = []


def session(sport, request_segments, response):
    cseq, sseq = 1000, 5000
    packets.append(Ether(src=MAC[CLIENT], dst=MAC[SERVER]) / IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=5060, flags="S", seq=cseq))
    packets.append(Ether(src=MAC[SERVER], dst=MAC[CLIENT]) / IP(src=SERVER, dst=CLIENT) / TCP(sport=5060, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
    cseq += 1
    sseq += 1
    packets.append(Ether(src=MAC[CLIENT], dst=MAC[SERVER]) / IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=5060, flags="A", seq=cseq, ack=sseq))
    for seg in request_segments:
        packets.append(Ether(src=MAC[CLIENT], dst=MAC[SERVER]) / IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=5060, flags="PA", seq=cseq, ack=sseq) / seg)
        cseq += len(seg)
        packets.append(Ether(src=MAC[SERVER], dst=MAC[CLIENT]) / IP(src=SERVER, dst=CLIENT) / TCP(sport=5060, dport=sport, flags="A", seq=sseq, ack=cseq))
    packets.append(Ether(src=MAC[SERVER], dst=MAC[CLIENT]) / IP(src=SERVER, dst=CLIENT) / TCP(sport=5060, dport=sport, flags="PA", seq=sseq, ack=cseq) / response)
    sseq += len(response)
    packets.append(Ether(src=MAC[CLIENT], dst=MAC[SERVER]) / IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=5060, flags="A", seq=cseq, ack=sseq))
def request(cseq):
    return (
        "REGISTER sip:example.com SIP/2.0\r\n"
        "Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK%d\r\n"
        "From: <sip:alice@example.com>;tag=1234\r\n"
        "To: <sip:alice@example.com>\r\n"
        "Call-ID: 1234567890@192.168.1.10\r\n"
        "CSeq: %d REGISTER\r\n" % (cseq, cseq)
        + "".join("X-Header-%02d: %s\r\n" % (i, "a" * 40) for i in range(20))
        + "Content-Length: 0\r\n"
        "\r\n"
    ).encode()


response = (
    b"SIP/2.0 200 OK\r\n"
    b"Call-ID: 1234567890@192.168.1.10\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

m = request(1) + request(2)
session(40001, [m[i : i + 1] for i in range(len(m))], response)

wrpcap("input.pcap", packets)
