Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

The three packets should trigger all three signatures, but since DROP signature
has higher priority, all packets are dropped before other alerts are generated.
The packets are considered as being from a single flow, and with the first
packet being dropped, the whole flow is dropped, generated a single alert for
sid 1.

PCAP
====
pcap generated with scapy.

