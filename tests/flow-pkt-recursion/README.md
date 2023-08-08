# Test Purpose

Tests comparing of flows with and without recursion level set. Ignoring
recursion level in flows is useful for devices that terminate the tunnel
and also use a packet pickup like netmap pipes. This causes packets sent
from the Suricata running device to not have tunneled headers but the reply
traffic does.

The middleware tests are checking when the suricata running device is
analysing tunneled packets and is not a tunnel terminator. This case
should not be affected by recursion level in flow.

The terminated tests are checking when the suricata running device is
terminating the tunnel, either as a client or server. This is the case
where recursion level can affect the flows for packet pickup types
described above.

## PCAP

This PCAP was generated with scapy.