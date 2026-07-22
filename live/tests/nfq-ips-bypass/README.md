---
tags:
- bypass
- nfq
---

# NFQ IPS with capture bypass test

Test NFQ IPS mode with capture (offload) bypass. The test checks that packets
are bypassed by Suricata, but uses a client and server to verify that the
traffic still flows.

When a flow is bypassed, Suricata ORs `nfq.bypass-mark` into the NFQUEUE verdict.
The test's `before` script installs a conntrack/CONNMARK ruleset in the DUT
namespace that saves that mark onto the connection and then accepts any
subsequent marked packet without queueing it. Suricata therefore stops seeing
the flow entirely while the endpoints keep talking. This is the NFQ equivalent
of the af-packet XDP capture bypass in `../afp-ips-xdp-bypass`.
