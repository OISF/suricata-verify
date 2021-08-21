#!/usr/bin/env python
from scapy.all import *
import base64

# NOTE: state.csv must be sorted with sort once generated

state_file = open("expected/state.csv", 'wb')

pkts = []

for i in range(1200):
    hostname = 'test' + str(i) + '.example.com'
    pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
        Dot1Q(vlan=6)/ \
        IP(dst='1.2.3.4', src='5.6.7.8')/UDP(dport=53)/DNS(id=1, rd=1, qd=DNSQR(qname=hostname))
    state_file.write(base64.b64encode(bytes(hostname, 'utf-8')))
    state_file.write(b'\n')

wrpcap('input.pcap', pkts)

state_file.close()
