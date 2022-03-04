#!/usr/bin/env python
from scapy.all import *

pkts = []

load_layer("http")
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=63, flags='P''A')/HTTP()/HTTPRequest(Method='GET', Path=' / ', Http_Version='HTTP/1.1', Host='www.emergingthreats.net', User_Agent='Mozilla/5.0 (X11; U; Linux i686; es-ES; rv:1.9.0.13) Gecko/2009080315 Ubuntu/8.10 (intrepid) Firefox/3.0.13', Accept='text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8', Accept_Language='es-es,es;q=0.8,en-us;q=0.5,en;q=0.3', Accept_Encoding='gzip,deflate', Accept_Charset='ISO-8859-1,utf-8;q=0.7,*;q=0.7', Content_Type='Apache<!DOCTYPE html PUBLIC')

wrpcap('input.pcap', pkts)
