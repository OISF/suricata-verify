# ike-ikev1-proposal-recursion-dos

This test reproduces an unbounded recursion (stack exhaustion) in Suricata's
IKEv1 application-layer parser. A single unauthenticated IKE/ISAKMP datagram on
UDP/500, carrying a Proposal payload nested 5000 levels deep (12 bytes per
level, so roughly 60 KB, emitted here as IP fragments), drives the mutual
recursion `parse_payload()` -> `parse_proposal_payload()` in
`rust/src/ike/parser.rs` once per level. There is no depth cap, so the recursion
depth is bounded only by the packet size and overruns the worker thread stack,
crashing the Suricata worker (a remote pre-auth denial of service). IKE is
enabled by default, so the sensor only has to observe the packet.

https://redmine.openinfosecfoundation.org/issues/8800

## Scope caveat (why the 512 KiB stack)

The overflow happens once the recursion exceeds the available thread stack. On a
worker thread with Suricata's documented 512 KiB stack floor a single datagram
overflows at a depth of about 2400 levels. This test therefore forces that floor
with `--set threading.stack-size=512kb`. On a glibc build left at the default
8 MiB thread stack a single datagram is not deep enough to overflow, so the
crash there would need either a tuned/smaller stack or repeated packets; the
512 KiB floor (also the effective situation on musl/Alpine and on Windows, and
on any deployment that tunes `threading.stack-size` down) is the in-scope,
single-datagram-reachable case.

## Regenerating the pcap

`input.pcap` is produced by `gen_pcap.py` (requires scapy):

```
python3 gen_pcap.py --levels 5000 --out input.pcap
```

The nested-chain construction (proposal header, forced Transform placeholder,
inner Proposal generic payload) matches the parser dispatch in
`rust/src/ike/ikev1.rs` and `rust/src/ike/parser.rs`.
