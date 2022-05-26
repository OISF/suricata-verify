Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

The second packet should match rule sid 2 first, meaning no alerts are generated for it.
Sids 1 and 3 should generate alerts for the other packets.

PCAP
====
pcap generated with scapy.

