# DPDK IDS segmented mbufs

Verifies that Suricata inspects segmented (chained) mbufs intact in DPDK IDS
mode, and drops them without processing when `segmented-mbufs` is disabled.

Two DPDK pcap virtual PMDs capture the same traffic of the tap bridge `br0`,
`net_pcap0` with `segmented-mbufs` enabled and `net_pcap1` with it disabled.
The interface MTU of 256 sizes the mbufs to 1024 bytes and the bridged path
runs with a 9000 byte MTU. The client pings with 542 byte frames (1 mbuf),
1442 byte frames (2 mbufs, fit the packet buffer) and 9014 byte frames
(9 mbufs, extend the packet buffer). The rules require an intact ICMP checksum
over the whole payload and the ping pattern in its last bytes.

`net_pcap0` inspects all echo requests. `net_pcap1` inspects the 542 byte one
and counts the chained requests and replies in `capture.dpdk.segmented_drops`.

## Reference

- Redmine Ticket: https://redmine.openinfosecfoundation.org/issues/6012
