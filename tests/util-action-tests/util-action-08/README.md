Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

The three packets should trigger all three signatures, but since with the
default settings PASS has higher priority, the DROP and ALERT signatures won't
generate alerts, as all packets trigger sid 2 (PASS).

PCAP
====
pcap generated with scapy.

