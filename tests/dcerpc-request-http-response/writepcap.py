#!/usr/bin/env python
from scapy.all import *

pkts = []

load_layer("http")
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=63, flags='P''A')/DceRpc()
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    IP(dst='5.6.7.8', src='1.2.3.4')/TCP(sport=63, dport=6666, flags='P''A')/HTTP()/HTTPResponse(Http_Version='HTTP/1.0', Status_Code='200', Reason_Phrase='OK', Content_Type='text/html', Content_Length=7)
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=63, flags='A')

wrpcap('input.pcap', pkts)
