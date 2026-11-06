#!/usr/bin/env python3

# DNS over UDP where the first packet seen comes from the server and is not
# recognized as DNS (a truncated response), followed by a query from the
# client and its response.

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"
MAC = {CLIENT: "00:00:00:00:00:01", SERVER: "00:00:00:00:00:02"}


def pkt(src, dst, sport, dport, data):
    return (
        Ether(src=MAC[src], dst=MAC[dst])
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
        / data
    )


def response(id, name, address):
    return DNS(
        id=id,
        qr=1,
        aa=1,
        qd=DNSQR(qname=name),
        an=DNSRR(rrname=name, rdata=address),
    )


packets = [
    pkt(SERVER, CLIENT, 53, 40001, bytes(response(1, "cut.example", "10.0.0.1"))[:8]),
    pkt(CLIENT, SERVER, 40001, 53, DNS(id=2, rd=1, qd=DNSQR(qname="query.example"))),
    pkt(SERVER, CLIENT, 53, 40001, response(2, "query.example", "10.0.0.2")),
]

wrpcap("input.pcap", packets)
