---
tags:
- legacy-afpdpdk
- legacy-afp
---

# AF_PACKET IDS tpacket argument 3 autofp test

Ports `qa/live/afp-ids.sh 3 autofp` from the Suricata repository. The legacy
script maps argument `3` to `af-packet.1.tpacket-v3=false`; this port preserves
that behavior while replacing default-gateway traffic with deterministic ICMP
traffic on the live framework's `10.200.0.0/24` IDS bridge.

The test covers packet capture, datasets, rule reload, interface and runmode
socket commands, and hostbit management.
