# Description

Regression guard for the TCP timestamp (PAWS) handling of ticket 8991.

A client sends three 100 byte segments A, B and C, 5ms apart, so their
timestamps increase in send order. The network delays A by 15ms and the
server receives B, C, then A. The gap filling A carries the lowest TSval
of the three.

This is valid traffic. RFC 7323 section 4.3 only updates TS.Recent from a
segment with `SEG.SEQ <= Last.ACK.sent`, so B and C, which arrive over a hole,
do not update it. Linux implements this in `tcp_replace_ts_recent()`. The
receiving Linux stack accepts A, acknowledges all three segments with TSecr set
to the TSval of A, and its application receives all 300 bytes.

An engine that raises its timestamp baseline from B or C rejects A with
`pkt_invalid_timestamp`. The data in A is then missing from the reassembled
stream, while the endpoint has received it.

# PCAP

Captured from real traffic between two unmodified Linux 7.2 TCP stacks, each
in its own network namespace, connected through a third namespace acting as a
router. The capture was taken on the router interface facing the server,
after the reordering point.

- The client application marks segment A with DSCP CS1 (TOS 0x20) by setting
  `IP_TOS` on the socket around the first write. B and C are not marked.
- The router delays only marked packets by 15ms using a `prio` qdisc with a
  `u32` TOS filter and a `netem` child.
- The router delays all server to client packets by 200ms. This gives the path a
  WAN-like RTT, so the 15ms reordering stays inside the sender's RACK
  reordering window and does not cause a retransmission.
- Checksum offload and GRO/GSO/TSO are disabled on all veth interfaces.

The data carries the markers `C2S-SEG-A`, `C2S-SEG-B` and
`C2S-SEG-C`. The text `C2S-A-TAIL:C2S-B-HEAD` spans the A/B
segment boundary, so only stream reassembly can match it.
