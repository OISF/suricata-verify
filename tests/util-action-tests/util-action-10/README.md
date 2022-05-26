Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

The three packets should trigger all three signatures, but since DROP and ALERT
have higher priority, only those two generate alerts, as the PASS rule won't
take place.

PCAP
====
pcap generated with scapy.

