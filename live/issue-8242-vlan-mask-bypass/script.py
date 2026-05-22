#!/usr/bin/env python
from scapy.all import Ether, Dot1Q, IP, UDP, Raw, wrpcap


def vlan_pkt(payload):
    return (
        Ether()
        / Dot1Q(vlan=42)
        / IP(src="10.1.2.4", dst="10.1.2.3")
        / UDP(sport=12345, dport=12346)
        / Raw(load=payload)
    )


pkts = [
    vlan_pkt(b"byps"),  # matches sid:1 with bypass; installs eBPF map entry
    vlan_pkt(b"stuf"),  # same flow; expected to be dropped in kernel after fix
    vlan_pkt(b"stuf"),  # same flow; expected to be dropped in kernel after fix
]

wrpcap("vlan-flow.pcap", pkts)
