#!/usr/bin/env python3
#
# Generate input.pcap: a single IPv6/ICMPv6 echo request whose source address
# falls inside the range 2001:db8::1-2001:db8::ff used by test.rules.
#
# The pcap is written with linktype RAW (101) so it carries bare L3 bytes.

from scapy.all import IPv6, ICMPv6EchoRequest, wrpcap

pkt = IPv6(src="2001:db8::10", dst="2001:db8::ffff") / ICMPv6EchoRequest()

wrpcap("input.pcap", [pkt], linktype=101)
