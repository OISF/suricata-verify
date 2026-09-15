# Description

Live test for the AF_PACKET eBPF bypass when `vlan.use-for-tracking: no`.

Before the fix, `AFPBypassCallback` and `AFPXDPBypassCallback` write the
raw VLAN id into the eBPF `flow_table_v4` map key, while the kernel-side
XDP program writes zero (because `use-for-tracking` is off). The map
lookup misses, post-bypass packets on the same flow keep reaching
userspace, and `sid:2` fires for every one of them.

After the fix the userspace callbacks AND `g_vlan_mask` against `vlan_id`
before insert, so the keys match the kernel side and the kernel drops
subsequent packets on the bypassed flow. `sid:2` should never fire in
the eve log, and the flow should show `state: bypassed` /
`bypass: capture`.

# Ticket

https://redmine.openinfosecfoundation.org/issues/8242

# PCAP

Crafted with scapy `script.py`. Three UDP packets on the same 5-tuple,
all VLAN-tagged (vlan=42). First packet carries `byps` and triggers the
bypass rule; the remaining two carry `stuf` and are the post-bypass
batch.
