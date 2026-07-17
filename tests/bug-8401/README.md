# bug-8401

Tests for the threshold-hash telemetry counters:

- `detect.thresholds.entries` — total number of entries in the hash
- `detect.thresholds.nonempty_buckets` — number of non-empty buckets
- `detect.thresholds.max_bucket_depth` — deepest non-empty bucket
- `detect.thresholds.avg_bucket_depth` — integer average over non-empty
  buckets (= `entries` / `nonempty_buckets`, truncated)

Each sub-test populates the threshold hash in a different way — or
deliberately leaves it empty — and asserts the counter values that
result.

## Bucket collisions

For IPv4 keys the threshold hash uses `addr_data32[0]` directly, so
sources (or destinations) that vary only in the high-order octets of
the address share the same low bits and collide into a single bucket.
That's why tests 02, 04, 05, and 06 see five entries pile up in one
bucket and report `max == avg`. Test 07 deliberately mixes two
`/8` prefixes to land entries in two different buckets so that
`max != avg`.

## Sub-tests

| Test  | Keyword / track            | Hash population                                    | entries / nonempty / max / avg |
|-------|----------------------------|----------------------------------------------------|--------------------------------|
| 01    | `threshold` by_src         | 1 source, 1 entry                                  | 1 / 1 / 1 / 1                  |
| 02    | `threshold` by_src         | 5 sources in `10.0.0.X`, all collide               | 5 / 1 / 5 / 5                  |
| 03    | (no threshold keyword)     | hash stays empty                                   | 0 / 0 / 0 / 0                  |
| 04    | `threshold` by_rule        | all packets collapse to one key (shares -02 pcap)  | 1 / 1 / 1 / 1                  |
| 05    | `detection_filter` by_src  | exercises the detection_filter path (shares -02)   | 5 / 1 / 5 / 5                  |
| 06    | `threshold` by_dst         | 5 destinations in `192.168.1.X`, all collide       | 5 / 1 / 5 / 5                  |
| 07    | `threshold` by_src         | 3 sources in `10.0.0.X` + 1 source in `11.0.0.X`   | 4 / 2 / 3 / 2                  |
| 08    | `threshold` by_src         | 3 sources in `10.0.0.X` + 2 sources in `11.0.0.X`  | 5 / 2 / 3 / 2 (real avg 2.5)   |

## What is not covered

Depth decrease on entry expiry is not tested here. `ThresholdsExpire`
runs from the flow-manager thread on an async cadence; in offline pcap
replay the pcap finishes in milliseconds of wall-clock time before the
flow manager reliably gets a chance to run expire, so the final stats
snapshot is racy. That property is better validated with a C unit test.
