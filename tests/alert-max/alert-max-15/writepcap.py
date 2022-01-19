#!/usr/bin/env python
from scapy.all import *

pkts = list()
pkts.append(IP()/TCP())

wrpcap('input.pcap', pkts)
