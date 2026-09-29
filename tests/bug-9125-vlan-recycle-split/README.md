Test that a triple tagged (QinQinQ) frame does not split the flow of a
stream that follows it.

Ticket: https://redmine.openinfosecfoundation.org/issues/9125

## PCAP

Created with `writepcap.py` (scapy). A TCP stream carries `FOO` and `BAR`
in two separate segments, so the signature in `test.rules` can only match
on reassembled data. Between the two segments sit 3 frames of an unrelated
flow, each carrying 3 802.1Q tags (vlan 100/200/300, verified with
`tshark -r input.pcap -T fields -e vlan.id`).

The priming frames are not part of the stream and never get an answer. All
they do is fill every vlan id slot of the pooled packet that decodes them.
Suricata recycles its packets through a per thread pool, and in single
threaded pcap file mode (`args: --runmode single`, which is what makes the
recycle tight and the result reproducible) the slot that just carried a
QinQinQ frame is the one handed out next. If the recycle path leaves one of
the slots behind, the `BAR` segment is keyed with the third vlan id of the
priming frame while the packets before it are not: the stream lands in two
Flow objects (3 + 2 packets to server) with the reassembly split over them,
and the signature does not fire.

See ../bug-9125-vlan-recycle-qinq for the same trace with 2 tags, which is
unaffected either way and shows that it is the third tag that matters.
