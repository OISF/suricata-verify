Control for ../bug-9125-vlan-recycle-split: the same stream and the same
priming frames, but with 2 802.1Q tags instead of 3.

Ticket: https://redmine.openinfosecfoundation.org/issues/9125

## PCAP

Created with `writepcap.py` (scapy); verified with
`tshark -r input.pcap -T fields -e vlan.id`, which reports 100,200 on the
priming frames.

A QinQ frame only reaches vlan_id[0] and vlan_id[1], and the packet pool
recycle path cleared those two even when it left the third slot of a
QinQinQ frame behind. So this trace gives one flow and one alert both
before and after the fix: it pins down that the differential in
../bug-9125-vlan-recycle-split comes from the third tag rather than from
the priming frames, the stream layout or the runmode.
