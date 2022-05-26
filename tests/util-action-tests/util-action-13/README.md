Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

As the DROP action has the higher priority, we expect that all packets generate
alert for sid 2, and sid 2 only.

PCAP
====
pcap generated with scapy.

