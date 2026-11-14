#!/usr/bin/env python3
"""
Craft the bug-9089 test pcap.

One UDP packet whose 8 byte header ends in ASCII digits that continue
into the payload:

  udp.hdr  offset 0-1  source port 5000
           offset 2-3  destination port 0x4130 ("A0")
           offset 4-5  length
           offset 6-7  checksum 0x3132 ("12")
  payload             "345x"

udp.hdr points into the packet, so the bytes behind it are the payload.
Converting the checksum digits with no length bound reads "12345"; the
"x" stops the conversion. byte_extract reads the "0" at offset 3 as a
count of 0.

Run with -k none: the checksum is not valid.
"""

from scapy.all import IP, UDP, Raw, wrpcap

ip = IP(src="10.1.1.1", dst="10.1.1.2")
udp = UDP(sport=5000, dport=0x4130, chksum=0x3132)
pkt = ip / udp / Raw(load=b"345x")
pkt.time = 1700000000
wrpcap("input.pcap", [pkt])
