#!/usr/bin/env python3

# SIP sessions over TCP picked up midstream: the capture starts with an ACK
# from the server, so the flow is created in the wrong direction and the first
# request is seen as sent to the client. INVITE is detected with a plain
# pattern, NOTIFY and OPTIONS with a pattern and the probing parser.

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


def session(sport, request, response):
    cseq, sseq = 1000, 5000
    packets.append(pkt(SERVER, CLIENT, 5060, sport, "A", sseq, cseq))
    packets.append(pkt(CLIENT, SERVER, sport, 5060, "PA", cseq, sseq, request))
    cseq += len(request)
    packets.append(pkt(SERVER, CLIENT, 5060, sport, "A", sseq, cseq))
    packets.append(pkt(SERVER, CLIENT, 5060, sport, "PA", sseq, cseq, response))
    sseq += len(response)
    packets.append(pkt(CLIENT, SERVER, sport, 5060, "A", cseq, sseq))


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


def sip(sport, method):
    session(
        sport,
        sip_message("%s sip:bob@example.com SIP/2.0" % method, method),
        sip_message("SIP/2.0 200 OK", method),
    )


sip(40001, "INVITE")
sip(40002, "NOTIFY")
sip(40003, "OPTIONS")

wrpcap("input.pcap", packets)
