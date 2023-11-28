#!/usr/bin/env python
from scapy.all import *

pkts = []
'''packet 1'''
pkts += IP(dst='172.16.4.19', src='172.16.1.1')/TCP(sport=1050, dport=5432, flags='S', window=65535, seq=0, options=[('MSS', 1460), ('SAckOK', '')])
'''packet 2'''
pkts += IP(src='172.16.4.19', dst='172.16.1.1')/TCP(dport=1050, sport=5432,
                flags='S''A', ack=1, window=5840, seq=0, options=[('MSS', 1460), ('SAckOK', '')])
'''packet 3'''
pkts += IP(dst='172.16.4.19', src='172.16.1.1')/TCP(sport=1050, dport=5432, flags='A', ack=1, window=65535, seq=1)
'''packet 4'''
pkts += IP(dst='172.16.4.19', src='172.16.1.1')/TCP(sport=1050, dport=5432, flags='P''A', ack=1, window=65535, seq=98080856)
'''packet 5'''
pkts += IP(src='172.16.4.19', dst='172.16.1.1')/TCP(dport=1050, sport=5432, flags='A', ack=37, window=5840, seq=1)
'''packet 6'''
pkts += IP(src='172.16.4.19', dst='172.16.1.1')/TCP(dport=1050, sport=5432, flags='P''A', ack=37, window=5840, seq=1)/":"
'''packet 7'''
pkts += IP(dst='172.16.4.19', src='172.16.1.1')/TCP(sport=1050, dport=5432, flags='A', ack=37, window=65534, seq=2)
'''packet 8'''
pkts += IP(src='172.16.4.19', dst='172.16.1.1')/TCP(dport=1050, sport=5432, flags='P''A', ack=37, window=5840, seq=2)/"p1r473.server.org\x01\n"
'''packet 9'''
pkts += IP(dst='172.16.4.19', src='172.16.1.1')/TCP(sport=1050, dport=5432, flags='P''A', ack=1363, window=64173, seq=37)
'''packet 10'''
pkts += IP(dst='172.16.4.19', src='172.16.1.1')/TCP(sport=1050, dport=5432, flags='F''P''A', ack=1363, window=64173, seq=53)
'''packet 11'''
pkts += IP(src='172.16.4.19', dst='172.16.1.1')/TCP(dport=1050, sport=5432, flags='P''A', ack=200, window=6432, seq=1363)/":"
'''packet 12'''
pkts += IP(dst='172.16.4.19', src='172.16.1.1')/TCP(sport=1050, dport=5432, flags='R''A', ack=1364, window=0, seq=200)

wrpcap('input.pcap', pkts)
