# DPDK TAP segmented mbufs with tx-segmented-mbufs disabled

Verifies that, in DPDK TAP mode with `tx-segmented-mbufs` disabled (the
default), Suricata does not forward segmented (chained) mbufs it cannot merge
into one mbuf, although TAP mode otherwise forwards every packet regardless of
the verdict.

It reuses the setup of `dpdk-segmented-mbufs-ips-tx-disabled` with
`copy-mode: tap`: the client pings with 542 byte frames (1 mbuf), 1442 byte
frames (2 mbufs) and 9014 byte frames (9 mbufs) through 1024 byte mbufs. Only
the 542 byte ping gets a reply. The chained echo requests are counted in
`capture.dpdk.segmented_drops` and do not alert.

## Reference

- Redmine Ticket: https://redmine.openinfosecfoundation.org/issues/6012
