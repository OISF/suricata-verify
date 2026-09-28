# DPDK IDS segmented mbufs

Verifies that Suricata inspects segmented (chained) mbufs intact in DPDK IDS
mode.

A DPDK pcap virtual PMD `net_pcap0` captures the traffic of the tap bridge
`br0`. The interface MTU of 256 sizes the mbufs to 1024 bytes and the bridged
path runs with a 9000 byte MTU. The test relies on `net_pcap` not enforcing the
interface MTU: larger frames still arrive, as chained mbufs, and a `net_pcap`
that enforces the MTU would drop them. The client pings with 542 byte frames
(1 mbuf), 1442 byte frames (2 mbufs, fit the packet buffer) and 9014 byte
frames (9 mbufs, extend the packet buffer). The rules require an intact ICMP
checksum over the whole payload and the ping pattern in its last bytes.

## Reference

- Redmine Ticket: https://redmine.openinfosecfoundation.org/issues/6012
