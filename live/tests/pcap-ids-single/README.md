---
tags:
- legacy-afpdpdk
- legacy-pcap
---

# Libpcap IDS single runmode test

Ports `qa/live/pcap.sh single` from the Suricata repository. It replaces
host-default-gateway traffic with deterministic ICMP traffic on the live
framework's `10.200.0.0/24` IDS bridge.

The test covers packet capture, IPv4 and IPv6 datasets, malformed dataset
input, rule reload, interface and runmode socket commands, and hostbit
management.
