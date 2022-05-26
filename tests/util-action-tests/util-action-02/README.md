Test based on former Suricata unit test from util-action file.

Expected Behavior
=================

For the second packet, we expect to only see an alert for sid 3, as DROP and
PASS here have higher priority. The other two packets should generate alerts,
since sid 2 isn't triggered for them.

PCAP
====
pcap generated with scapy.

