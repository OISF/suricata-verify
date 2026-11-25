# bug-8401

Tests for the threshold hash stats counters:

- `detect.thresholds.entries`: number of entries in the hash
- `detect.thresholds.nonempty_buckets`: number of non-empty buckets
- `detect.thresholds.max_bucket_depth`: largest number of entries in one
  bucket
- `detect.thresholds.avg_bucket_depth`: `entries` / `nonempty_buckets`,
  truncated to an integer

The threshold hash mixes a seed chosen at random on every run into the
hash of each address, so the bucket an entry lands in changes from run
to run. With one entry (or none) all four values are fixed, so tests 01,
03 and 04 check all of them. Tests with several entries check only
`entries`.

The bucket layout cases (several entries in one bucket, entries split
across buckets, a truncated average) and the removal paths (expire,
cleanup, remove, recycling at memcap) are covered by the
`THashBucketStatsTest` unit tests in `src/util-thash.c`, which use a hash
function that ignores the seed.

| Test | Keyword / track           | Hash population                                   | Checked                          |
|------|---------------------------|---------------------------------------------------|----------------------------------|
| 01   | `threshold` by_src        | 1 source, 1 entry                                 | 1 / 1 / 1 / 1                    |
| 02   | `threshold` by_src        | 5 sources                                         | `entries` 5                      |
| 03   | (no threshold keyword)    | hash stays empty                                  | 0 / 0 / 0 / 0                    |
| 04   | `threshold` by_rule       | all packets map to one entry (uses the 02 pcap)   | 1 / 1 / 1 / 1                    |
| 05   | `detection_filter` by_src | 5 sources (uses the 02 pcap)                      | `entries` 5                      |
| 06   | `threshold` by_dst        | 5 destinations                                    | `entries` 5                      |

The four-value columns are entries / nonempty_buckets / max_bucket_depth /
avg_bucket_depth.
