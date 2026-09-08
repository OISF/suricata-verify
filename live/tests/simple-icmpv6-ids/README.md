---
tags:
- icmp
- ipv6
---

A simple ICMPv6 IDS test. It assigns static IPv6 addresses to the client and
server, sends one echo request through the tap bridge, and verifies that
Suricata decodes and alerts on the IPv6 traffic.
