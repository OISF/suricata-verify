# Bug 7801 verification suite

This folder documents the regression tests that cover Redmine issue #7801 (cross-buffer
`byte_extract` and `byte_math`). Suricata caches byte keyword values per transaction so
later inspections (other buffers or directions) can reuse the produced values. All tests
use bidirectional (`=>`) rules with HTTP/1.1 pipelining to create multiple TXs that share
the same `det_ctx`. A spoiler TX's `byte_extract` or `byte_math` clobbers
`det_ctx->byte_values` before the target TX's toclient inspection. Without the per-TX
byte value cache, these tests fail (missed detection or false positive).

## Bidirectional test cases (`=>`)

These test cross-buffer byte variable usage across directions (toserver producer -> toclient
consumer). Each uses HTTP/1.1 pipelining with a spoiler TX that clobbers
`det_ctx->byte_values` before the first TX's toclient inspection.

- `bug-7801-01`: `http.uri` (toserver) -> `http.stat_code` (toclient) via `byte_test`. Pipelined spoiler TX extracts 99, real TX extracts 05; `byte_test: 48 > val`.
- `bug-7801-02`: `http.request_body` (toserver) -> `http.stat_code` (toclient) via `byte_test`. Pipelined spoiler TX extracts 99, real TX extracts 07; `byte_test: 48 > val`.
- `bug-7801-03`: `http.host` (toserver) -> `http.stat_msg` (toclient) via negated `isdataat`. Pipelined spoiler TX extracts 01, real TX extracts 08; `isdataat:!val,relative`.
- `bug-7801-04`: `http.uri` (toserver) `byte_extract` + `byte_math` -> `http.stat_msg` (toclient) via negated `isdataat`. Pipelined spoiler TX clobbers both byte values.

## Pipelined multi-TX test cases (`=>`)

These explicitly test the per-TX byte value cache with pipelined requests within a single
flow. Two requests are sent before any response, creating two TXs that share the same
`det_ctx`. All toserver inspections complete before toclient inspections begin, so the
second TX's byte values clobber the first's.

- `bug-7801-05`: Spoiler TX first (extracts 99), real TX second (extracts 05). `http.uri` -> `http.stat_code` via `byte_test`. Without cache: 0 alerts (missed). With cache: 1 alert.
- `bug-7801-06`: Real TX first (extracts 05), spoiler TX second (extracts 99). `http.uri` -> `http.stat_code` via `byte_test`. Without cache: 0 alerts (missed). With cache: 1 alert.
- `bug-7801-07`: False positive prevention. TX1 extracts 01 (should not alert), TX2 extracts 08 (should alert). `http.uri` -> `http.stat_msg` via negated `isdataat`. Without cache: 2 alerts (false positive). With cache: 1 alert.
- `bug-7801-08`: `byte_math` cache test. TX1: base=3, total=5 (should alert), TX2: base=40, total=70 (spoiler). `http.uri` -> `http.stat_code` via `byte_test`. Without cache: 0 alerts (missed). With cache: 1 alert.

## Original Redmine #1412 test case (`->`)

- `bug-7801-09`: Uses the exact rule and pcap from [Redmine #1412](https://redmine.openinfosecfoundation.org/issues/1412). Unidirectional (`->`, `flow:to_client`). `byte_extract` in `http_raw_header` extracts `Content-Length` value (11), `byte_test` in `file_data` compares against it using little-endian. Single TX, cross-buffer within the same direction.

## Structure

Each directory contains a Suricata rule, `test.yaml` spec, and either a `gen_pcap.py` script
or an `input.pcap` so `suricata-verify` can run them individually or as part of this suite.
