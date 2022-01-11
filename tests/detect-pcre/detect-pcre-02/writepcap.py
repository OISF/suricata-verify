#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=80, flags='P''A')/"GET / HTTP/1.1\r\nHost: www.emergingthreats.net\r\nUser-Agent: Mozilla/1.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8\r\nAccept-Encoding: gzip,deflate\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html; charset=utf-8\r\n\r\n15\r\n<!DOC"
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=90, flags='P''A')/"<!DOCTYPE html PUBLIC\r\n0\r\n\r\n"
wrpcap('input-pcre-05.pcap', pkts)