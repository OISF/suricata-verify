Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

The DROP rule (sid 3) will be triggered by all packets, and having the highest
priority, will make so that no other alerts will be registered by Suri.

PCAP
====
pcap generated with scapy.

