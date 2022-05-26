Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

For the second packet, we don't expect alerts, since it will be flagged by the
PASS sid (2). We expect alerts for sids 1 and 3 for the other two packets.

PCAP
====
pcap generated with scapy.

