Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

As the DROP and ALERT actions have higher priority, we expect that all packets generate
alerts for sids 2 and 3.

PCAP
====
pcap generated with scapy.

