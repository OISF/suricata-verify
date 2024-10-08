# Test Purpose

Tests comparing flows with and without recursion level set. Ignoring
recursion level in flows is useful for devices that run inline IPS and
terminate an unencrypted tunnel, like an IPv6 tunnel. Terminating the
tunnel causes ingress request and reply traffic to have different
headers. e.g.

request:  IPv4]ICMP] -> |IPS| -> IPv6]IPv4]ICMP]
reply:               <- |IPS| <- IPv6]IPv4]ICMP]

The terminated tests are checking when the suricata is an inline IPS
device that is terminating a tunnel. Both flow directions are tested,
first packet ingress on non-tunneled interface and first packet ingress
on tunneled interface.
This is the case where recursion level can affect the flows when IPS is
running inline IPS and terminating a tunnel.

Middleware tests check when the suricata device is analysing tunneled
packets and is not a tunnel terminator.
This case should not be affected by recursion level in flows.

## PCAP

This PCAP was generated with scapy.