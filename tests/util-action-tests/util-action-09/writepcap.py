#!/usr/bin/env python
from scapy.all import *

pkt1 = Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
        Dot1Q(vlan=6)/ \
        IP(dst='192.168.1.1', src='192.168.1.5')/TCP(sport=41424, dport=80)/"Hi all!\r\n"

pkt2 = Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
        Dot1Q(vlan=6)/ \
        IP(dst='192.168.1.5', src='192.168.1.1')/TCP(sport=80, dport=41424)/"Hi all!\r\n"

pkt3 = Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
        Dot1Q(vlan=6)/ \
        IP(dst='192.168.1.1', src='192.168.1.5')/TCP(sport=41424, dport=80,
                flags='P''A')/"Hi all!\r\n"

pkts = []
pkts += pkt1
pkts += pkt2
pkts += pkt3

wrpcap('input.pcap', pkts)
