#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Regenerates input.pcap for the netflow-exception-policy test.
#
# A single bare TCP ACK with HTTP GET payload, no preceding SYN.  When
# Suricata is configured with stream.midstream-policy = bypass it sees
# this segment midstream and applies the bypass exception policy on
# the flow, which is what this test asserts.

from scapy.all import Ether, IP, TCP, Raw, wrpcap


def main():
    pkt = (
        Ether(src="00:15:5d:59:44:4a", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="10.0.0.1", dst="10.0.0.2", id=1, ttl=64)
        / TCP(sport=12345, dport=80, seq=1000, ack=1, flags="A", window=8192)
        / Raw(load=b"GET / HTTP/1.0\r\n\r\n")
    )
    wrpcap("input.pcap", [pkt])


if __name__ == "__main__":
    main()
