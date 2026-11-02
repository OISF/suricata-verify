#!/usr/bin/env python3

# OPTIONS and UPDATE, methods shared by SIP and HTTP/1, over TCP: SIP
# requests sent in one segment, split in the request line and byte by
# byte, and HTTP requests that must stay HTTP.

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


def session(sport, dport, request_segments, response):
    cseq, sseq = 1000, 5000
    packets.append(pkt(CLIENT, SERVER, sport, dport, "S", cseq, 0))
    packets.append(pkt(SERVER, CLIENT, dport, sport, "SA", sseq, cseq + 1))
    cseq += 1
    sseq += 1
    packets.append(pkt(CLIENT, SERVER, sport, dport, "A", cseq, sseq))
    for seg in request_segments:
        packets.append(pkt(CLIENT, SERVER, sport, dport, "PA", cseq, sseq, seg))
        cseq += len(seg)
        packets.append(pkt(SERVER, CLIENT, dport, sport, "A", sseq, cseq))
    packets.append(pkt(SERVER, CLIENT, dport, sport, "PA", sseq, cseq, response))
    sseq += len(response)
    packets.append(pkt(CLIENT, SERVER, sport, dport, "A", cseq, sseq))


def sip_message(first_line, method):
    return (
        "%s\r\n"
        "Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK1234567890\r\n"
        "From: <sip:alice@example.com>;tag=1234\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: 1234567890@192.168.1.10\r\n"
        "CSeq: 1 %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n" % (first_line, method)
    ).encode()


def sip(sport, method, uri="sip:bob@example.com", split=None):
    m = sip_message("%s %s SIP/2.0" % (method, uri), method)
    if split == "bytes":
        segments = [m[i : i + 1] for i in range(len(m))]
    elif split:
        segments = [m[:split], m[split:]]
    else:
        segments = [m]
    session(sport, 5060, segments, sip_message("SIP/2.0 200 OK", method))


def http(sport, request, split=None):
    segments = [request[:split], request[split:]] if split else [request]
    session(sport, 80, segments, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")


long_uri = "sip:" + "b" * 400 + "@example.com"

# SIP
sip(40001, "OPTIONS")
sip(40002, "UPDATE")
# request line split before the SIP version
sip(40003, "OPTIONS", long_uri, split=300)
sip(40004, "UPDATE", long_uri, split=300)
# NOTIFY is probed as well, but not shared with HTTP/1
sip(40005, "NOTIFY", long_uri, split=300)
sip(40006, "OPTIONS", split="bytes")

# HTTP/1
http(41001, b"OPTIONS * HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
http(41002, b"UPDATE /repo HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
# "SIP/" in the URI and in a header
http(41003, b"OPTIONS /SIP/2.0 HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: SIP/2.0\r\n\r\n")
http(41004, b"OPTIONS /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n", split=12)
# request line longer than the SIP probe limit, split before its end
http(41005, b"OPTIONS /" + b"a" * 2000 + b" HTTP/1.1\r\nHost: www.example.com\r\n\r\n", split=1400)

wrpcap("input.pcap", packets)
