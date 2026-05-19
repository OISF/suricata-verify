# DPDK Segmented Mbufs Test (Ticket #6012)

Verifies that Suricata correctly handles segmented (chained) mbufs in DPDK mode.

## How it works

- Runs in DPDK mode using `net_pcap` vdev
- Packets larger than mbuf size are segmented across multiple mbufs
- If segmented mbuf handling is broken, packet data is corrupted and alerts fail

## Reference

- Redmine Ticket: https://redmine.openinfosecfoundation.org/issues/6012
- Based on: tests/tls/tls-certs-alert (chosen for its large packets that force mbuf segmentation)
