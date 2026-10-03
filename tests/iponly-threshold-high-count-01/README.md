# iponly-threshold-high-count-01

Documents that a count-based `threshold` with `track by_flow` can never fire on
an IP-only rule when the count exceeds the per-flow match-event ceiling.

## Why

An IP-only rule matches only on IP addresses, which are constant for a flow, so
the detection engine evaluates it just **once per flow direction** (the first
`to_server` and first `to_client` packet) -- at most 2 match events per
bidirectional flow. A `type threshold` keyword alerts only after `count` match
events accumulate, and with `track by_flow` the counter is per-flow and resets
per-flow. An IP-only rule can therefore never push more than 2 events into one
flow's counter, so any `count > 2` can **never fire**, for any traffic volume.

## Traffic

`icmp-multiflow.pcap`: 5 independent bidirectional ICMP echo flows
(`10.1.1.1..5 <-> 10.2.2.2`), i.e. **2** IP-only match events per flow.

## Rules and expected results

| sid | matching | track | count | alerts | meaning |
|-----|----------|---------|-------|--------|---------|
| 1 | IP-only | by_flow | 5 | 0 | **never fires** -- per-flow ceiling of 2 events |
| 2 | IP-only | by_flow | 2 | 5 | control: reaches 2 per flow -> once per flow (5 flows) |

sid:1 is the documented behaviour. sid:2 is a control proving the rule matches
and that a by_flow threshold does fire at a reachable count, so sid:1's 0 is the
per-flow ceiling rather than a rule that never matched.

## Regenerating the pcap

```python
from scapy.all import Ether, IP, ICMP, wrpcap
DST = "10.2.2.2"
pkts = []
for i in range(1, 6):
    src = f"10.1.1.{i}"
    icmp_id = 0x1000 + i
    pkts.append(Ether()/IP(src=src, dst=DST)/ICMP(type=8, id=icmp_id, seq=1)/(b"x"*32))
    pkts.append(Ether()/IP(src=DST, dst=src)/ICMP(type=0, id=icmp_id, seq=1)/(b"x"*32))
for idx, p in enumerate(pkts):
    p.time = idx * 0.01
wrpcap("icmp-multiflow.pcap", pkts)
```
