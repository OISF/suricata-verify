Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

As the DROP action has the higher priority, we expect that all packets generate
alert for sid 3.

PCAP
====
pcap generated with scapy.

