#!/usr/bin/env python3
"""Generate the TFTP request/reply pcap used by this regression test."""

import sys

from scapy.all import Ether, IP, UDP, Raw, wrpcap

CLIENT = "10.0.0.2"
SERVER = "10.0.0.1"
CLIENT_PORT = 40000
SERVER_PORT = 69
CLIENT_MAC = "02:00:00:00:00:02"
SERVER_MAC = "02:00:00:00:00:01"


def main(out):
    rrq = b"\x00\x01rfc1350.txt\x00octet\x00"
    ack = b"\x00\x04\x00\x01"

    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT, dst=SERVER)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / Raw(rrq)
    )
    request.time = 1.0

    reply = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER, dst=CLIENT)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / Raw(ack)
    )
    reply.time = 1.001

    wrpcap(out, [request, reply])


if __name__ == "__main__":
    main(sys.argv[1])
