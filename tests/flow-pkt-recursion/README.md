# Test Purpose

Tests comparing flows with and without recursion level set. Ignoring
recursion level in flows is useful for devices that run inline IPS and
terminate an unencrypted tunnel, like an IPv6 tunnel. Terminating the
tunnel causes ingress request and reply traffic to have different
headers. e.g.

request:  IPv4]ICMP] -> |IPS| -> IPv6]IPv4]ICMP]
reply:               <- |IPS| <- IPv6]IPv4]ICMP]

There are tests for both IDS and IPS.

The (ids|ips)-tunnel tests are checking when Suricata is an inline device
that is terminating a tunnel.
In this case, the request and reply traffic will have different recursion
levels, due to the tunneling headers.

The (ids|ips)-middleware tests check when the suricata device is analysing tunneled
packets and is not a tunnel terminator.
This case should not be affected by recursion level in flows.

## PCAP

This PCAP was generated with scapy.