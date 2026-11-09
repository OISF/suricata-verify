#!/usr/bin/env python3

# Requests using OPTIONS and UPDATE, methods shared by SIP and HTTP/1, over
# TCP: HTTP requests whose target cannot be a SIP Request-URI, also when the
# request line ends with the SIP version or is never completed, and a SIP
# request without a space after the method.

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"
MAC = {CLIENT: "00:00:00:00:00:01", SERVER: "00:00:00:00:00:02"}

packets = []


def pkt(src, dst, sport, dport, flags, seq, ack, data=b""):
    return (
        Ether(src=MAC[src], dst=MAC[dst])
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        / data
    )


def session(sport, dport, request, response=None):
    cseq, sseq = 1000, 5000
    packets.append(pkt(CLIENT, SERVER, sport, dport, "S", cseq, 0))
    packets.append(pkt(SERVER, CLIENT, dport, sport, "SA", sseq, cseq + 1))
    cseq += 1
    sseq += 1
    packets.append(pkt(CLIENT, SERVER, sport, dport, "A", cseq, sseq))
    packets.append(pkt(CLIENT, SERVER, sport, dport, "PA", cseq, sseq, request))
    cseq += len(request)
    packets.append(pkt(SERVER, CLIENT, dport, sport, "A", sseq, cseq))
    if response is None:
        # the client closes before completing the request line
        packets.append(pkt(CLIENT, SERVER, sport, dport, "FA", cseq, sseq))
        cseq += 1
        packets.append(pkt(SERVER, CLIENT, dport, sport, "FA", sseq, cseq))
        sseq += 1
        packets.append(pkt(CLIENT, SERVER, sport, dport, "A", cseq, sseq))
        return
    packets.append(pkt(SERVER, CLIENT, dport, sport, "PA", sseq, cseq, response))
    sseq += len(response)
    packets.append(pkt(CLIENT, SERVER, sport, dport, "A", cseq, sseq))


HTTP_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

# HTTP/1
session(41001, 80, b"OPTIONS /index.html")
session(41002, 80, b"UPDATE /admin SIP/2.0\r\nHost: www.example.com\r\n\r\n", HTTP_RESPONSE)
session(41003, 80, b"OPTIONS\t/ HTTP/1.1\r\nHost: www.example.com\r\n\r\n", HTTP_RESPONSE)

# SIP
session(
    40001,
    5060,
    b"UPDATEsip:192.168.1.20;transport=TCP SIP/2.0\r\n"
    b"Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK1234567890\r\n"
    b"Call-ID: 1234567890@192.168.1.10\r\n"
    b"CSeq: 1 UPDATE\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n",
    b"SIP/2.0 200 OK\r\n"
    b"Call-ID: 1234567890@192.168.1.10\r\n"
    b"CSeq: 1 UPDATE\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n",
)

wrpcap("input.pcap", packets)
