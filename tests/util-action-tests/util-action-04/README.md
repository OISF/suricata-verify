Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

First and third sids will be triggered by all three packets. The second packet
won't trigger sid 1, for the PASS rule will bypass that.

PCAP
====
pcap generated with scapy.

