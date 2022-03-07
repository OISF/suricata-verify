#!/usr/bin/env python
from scapy.all import *

pkts = []

load_layer("http")
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=63, flags='P''A')/"POST /upload.cgi HTTP/1.1\r\nHost: www.server.lan\r\nContent-Type: multipart/form-data; boundary=---------------------------277531038314945\r\nContent-Length: 215\r\n\r\n-----------------------------277531038314945\r\nContent-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nfilecontent\r\n-----------------------------277531038314945--"

wrpcap('input.pcap', pkts)
