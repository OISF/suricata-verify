---
tags:
- dpdk
- dpdk-ids
---

# DPDK IDS using the AF_PACKET virtual PMD

Converts the `afp-ids-tpacket2-workers` live test to DPDK IDS. The live runner
creates its normal tap bridge in the DUT namespace. DPDK's AF_PACKET virtual
PMD attaches to `br0`, allowing Suricata to observe traffic forwarded by the
Linux bridge without owning physical PCI devices.

The test covers packet capture, datasets, rule reload, interface and runmode
socket commands, and hostbit management. This exercises Suricata's DPDK receive
path, but not a VFIO-bound hardware NIC.
