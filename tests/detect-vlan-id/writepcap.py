#! /usr/bin/env python3
#scapy version 2.5.0
from scapy.all import *

CLIENT_MAC = "11:11:11:11:11:11"
SERVER_MAC = "22:22:22:22:22:22"

CLIENT_IP = "1.1.1.1"
SERVER_IP = "2.2.2.2"

request = (Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
               Dot1Q(vlan=200) /
               Dot1Q(vlan=300) /
               Dot1Q(vlan=400) /
               IP(src=CLIENT_IP, dst=SERVER_IP) /
               ICMP(type=8))

response = Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER_IP, dst=CLIENT_IP)/ICMP(type=0)

wrpcap("input.pcap", [request, response], append=False)