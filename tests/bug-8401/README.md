# bug-8401

Tests for the threshold-hash bucket-depth counters
(`detect.thresholds.max_bucket_depth` and `detect.thresholds.avg_bucket_depth`).
Each sub-test exercises a different path that populates — or deliberately
does not populate — the threshold hash, and verifies the depth counters
reflect the expected state.

## Sub-tests

- **bug-8401-01** — `threshold: track by_src` with traffic from a single
  source. One hash entry; expect `max/avg_bucket_depth = 1`.

- **bug-8401-02** — `threshold: track by_src` with traffic from five
  distinct sources. Five hash entries colliding in one bucket; expect
  `max/avg_bucket_depth = 5`.

- **bug-8401-03** — Rule with no threshold keyword. Hash stays empty;
  expect `max/avg_bucket_depth = 0`.

- **bug-8401-04** — `threshold: track by_rule`. All packets collapse to
  the same key regardless of source; one hash entry; expect
  `max/avg_bucket_depth = 1`. Shares the pcap with `bug-8401-02`.

- **bug-8401-05** — `detection_filter: track by_src` exercises the
  detection-filter code path (separate keyword, same hash table). Five
  sources, five hash entries in one bucket; expect
  `max/avg_bucket_depth = 5`. Shares the pcap with `bug-8401-02`.

- **bug-8401-06** — `threshold: track by_dst`. Mirrors by_src, but keyed
  on destination — validates the `TRACK_DST` branch (including its cache
  shortcut). Five destinations; expect `max/avg_bucket_depth = 5`.

## What is not covered

Depth decrease on entry expiry is not tested here. `ThresholdsExpire`
runs from the flow-manager thread on an async cadence; in offline pcap
replay the pcap finishes in milliseconds of wall-clock time before the
flow manager reliably gets a chance to run expire, so the final stats
snapshot is racy. That property is better validated with a C unit test.
