---
tags:
- legacy-afpdpdk
- legacy-pcap
---

# Libpcap multi-tenant autofp test

Ports `qa/live/multi-tenant.sh autofp` from the Suricata repository. It runs
libpcap IDS capture on the framework's bridge while exercising tenant
registration, tenant reload, tenant removal, and the expected failure when
removing an unknown tenant through the command socket.
