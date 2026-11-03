# DPDK IPS segmented mbufs with tx-segmented-mbufs disabled

Verifies that, in DPDK IPS mode with `tx-segmented-mbufs` disabled (the
default), Suricata drops segmented (chained) mbufs it cannot merge into one
mbuf without inspecting them, and forwards contiguous packets.

DPDK's pcap virtual PMDs forward traffic inline between `client0` and
`server0`. The interface MTU of 256 sizes the mbufs to 1024 bytes and the path
runs with a 9000 byte MTU. The client pings with 542 byte frames (1 mbuf),
1442 byte frames (2 mbufs) and 9014 byte frames (9 mbufs). Only the 542 byte
ping gets a reply. The chained echo requests are counted in
`capture.dpdk.segmented_drops`, in `ips.blocked` with the drop reason
`ips.drop_reason.capture_error`, and do not alert.

## Reference

- Redmine Ticket: https://redmine.openinfosecfoundation.org/issues/6012
