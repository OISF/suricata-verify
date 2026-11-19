# Description

An ICMPv4 error embeds the datagram that caused it. That datagram can carry
IPv4 options, so its L4 header starts at the embedded IHL, not at the fixed
20-byte IPv4 header length. The decoder read the embedded TCP/UDP ports at
offset 20 regardless, so flow matching used option bytes as ports.

The pcap has two TCP flows, each followed by a destination-unreachable whose
embedded header is 24 bytes (IHL 6, Router Alert option):

- flow 1, `10.0.0.1:37892 -> 10.0.0.2:135`: the option bytes are
  `94 04 00 87`, which read as ports 37892,135. The embedded TCP header at
  offset 24 has 12345,54321. The error is not the flow's packet and must not
  be attached (flow counts 1 to_client packet).
- flow 2, `10.0.0.3:40000 -> 10.0.0.2:80`: the option bytes are
  `94 04 00 01`, read as 37892,1. The embedded TCP header at offset 24 has
  the flow's 40000,80, so the error is attached (flow counts 2 to_client
  packets).

Before the fix both checks fail: flow 1 counts 2 and flow 2 counts 1.

# PCAP

Crafted with scapy (`craft.py`, run as `craft.py <outdir>`); tshark parses
the embedded Router Alert options and the real TCP ports.
