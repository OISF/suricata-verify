# Description

Test full pcap logging with decoder tunnels: frames from configured
tunnels, from an unknown tunnel and not tunneled are all logged as
captured.

# Ticket

https://redmine.openinfosecfoundation.org/issues/7674

# PCAP

Crafted with scapy script.py. Full pcap logging is expected to write
input.pcap back as is.

The same inner UDP 5-tuple is sent twice over each of:
- VXLAN VNI 123 from 192.168.1.3, configured as tunnel id 2
- ERSPAN II session 321 from 192.168.1.4, configured as tunnel id 1
- VXLAN VNI 999 from 192.168.1.3, not configured
- no tunnel
