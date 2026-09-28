# DPDK IPS segmented mbufs

Verifies that Suricata forwards segmented (chained) mbufs in DPDK IPS mode
with `tx-segmented-mbufs` enabled, including the modifications of the inline
stream normalization.

DPDK's pcap virtual PMDs forward traffic inline between `client0` and
`server0`. The interface MTU of 256 sizes the mbufs to 1024 bytes and the path
runs with a 9000 byte MTU. The test relies on `net_pcap` not enforcing the
interface MTU: larger frames still arrive, as chained mbufs, and a `net_pcap`
that enforces the MTU would drop them. Raw sockets play the client and the
server.

After a TCP handshake, the client sends a segment and a second segment that
overlaps its second half with different data, once with 400 byte segments
(1 mbuf), once with 1400 byte segments (2 mbufs) and once with 8960 byte
segments (9014 byte frames in 9 mbufs, the overlap spans 5 of them). Suricata
replaces the overlapping data with the data it inspected first.

The server requires to receive the first segment intact and the second one
with the replaced data, both with valid checksums. Each session alerts once
and counts once in `ips.replaced`, and nothing is dropped.

## Reference

- Redmine Ticket: https://redmine.openinfosecfoundation.org/issues/6012
