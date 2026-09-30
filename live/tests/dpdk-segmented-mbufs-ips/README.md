# DPDK IPS segmented mbufs

Verifies that Suricata forwards segmented (chained) mbufs in DPDK IPS mode,
including the modifications of the `replace` keyword and of the inline stream
normalization.

DPDK's pcap virtual PMDs forward traffic inline between `client0` and
`server0`. The interface MTU of 256 sizes the mbufs to 1024 bytes and the path
runs with a 9000 byte MTU. Raw sockets play the client and the server:

- Rules replace the last bytes of a 500 byte UDP datagram (1 mbuf) and of an
  8972 byte one (9 mbufs).
- After a TCP handshake, the client sends a segment and a second segment that
  overlaps it with different data, once with 400 byte segments (1 mbuf) and
  once with 1400 byte segments (2 mbufs). Suricata replaces the overlapping
  data with the data it inspected first.

The server requires to receive every modification with valid checksums and
the unmodified segments intact.

## Reference

- Redmine Ticket: https://redmine.openinfosecfoundation.org/issues/6012
