#!/usr/bin/env python3

# SIP over UDP with midstream enabled. In the first two flows the client's
# request is detected first, then the server sends a request of its own,
# NOTIFY detected with the probing parser and MESSAGE with a plain pattern,
# before answering the client and receiving another request: the flow must
# not be reversed. In the third flow a response is seen first, so the flow
# is reversed before the client's request.

from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"
MAC = {CLIENT: "00:00:00:00:00:01", SERVER: "00:00:00:00:00:02"}

packets = []


def pkt(src, dst, sport, dport, data):
    return (
        Ether(src=MAC[src], dst=MAC[dst])
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
        / data
    )


def sip_message(first_line, method, cseq=1):
    return (
        "%s\r\n"
        "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK1234567890\r\n"
        "From: <sip:alice@example.com>;tag=1234\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: 1234567890@192.168.1.10\r\n"
        "CSeq: %d %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n" % (first_line, cseq, method)
    ).encode()


def request(method, cseq=1):
    return sip_message("%s sip:bob@example.com SIP/2.0" % method, method, cseq)


def response(method, cseq=1):
    return sip_message("SIP/2.0 200 OK", method, cseq)


def server_request_first_detected(sport, server_method):
    packets.append(pkt(CLIENT, SERVER, sport, 5060, request("OPTIONS")))
    packets.append(pkt(SERVER, CLIENT, 5060, sport, request(server_method)))
    packets.append(pkt(SERVER, CLIENT, 5060, sport, response("OPTIONS")))
    packets.append(pkt(CLIENT, SERVER, sport, 5060, request("REGISTER", 2)))


server_request_first_detected(40001, "NOTIFY")
server_request_first_detected(40002, "MESSAGE")

# response seen first
packets.append(pkt(SERVER, CLIENT, 5060, 40003, response("OPTIONS")))
packets.append(pkt(CLIENT, SERVER, 40003, 5060, request("REGISTER", 2)))

wrpcap("input.pcap", packets)
