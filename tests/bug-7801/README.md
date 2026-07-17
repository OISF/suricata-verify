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

## Multi-pass toclient restore test (`=>`)

This test validates the memcpy-based byte_values restoration.
The rule uses two toclient buffers at different progress levels (`http.stat_code` at
`RESPONSE_LINE` and `file.data` at `RESPONSE_BODY`), causing the detect engine to make
two separate toclient inspection passes per TX. A pointer-swap restore corrupts the
per-TX state between those two passes; a memcpy-based restore keeps each TX's state
stable so both TXs alert correctly.

- `bug-7801-10`: Two pipelined TXs, both should match (count: 2). `http.uri` (toserver)
  -> `http.stat_code` + `file.data` (toclient) via `byte_test` in string mode. TX1
  extracts 11, body yields 22 (22 > 11); TX2 extracts 88, body yields 99 (99 > 88).
  Without cache: 0 alerts. With cache: 2 alerts.

## Original Redmine #1412 test case (`->`)

- `bug-7801-09`: Uses the exact rule and pcap from [Redmine #1412](https://redmine.openinfosecfoundation.org/issues/1412). Unidirectional (`->`, `flow:to_client`). `byte_extract` in `http_raw_header` extracts `Content-Length` value (11), `byte_test` in `file_data` compares against it using little-endian. Single TX, cross-buffer within the same direction.

## Unidirectional multi-packet tests (`->`)

These tests cover cases where a unidirectional rule's producer and consumer engines sit
at different TX progress levels (e.g., `http.stat_code` at `RESPONSE_LINE` and
`file.data` at `RESPONSE_BODY`). The producer fires on an earlier packet; the consumer
fires when a later packet advances `tx_progress` far enough to reach it. Any other
connection processed between those two packets clobbers `det_ctx->byte_values` before
the consumer runs. The per-TX cache must apply to unidirectional rules to protect these
scenarios.

- `bug-7801-11`: Missed detection via `byte_extract`. Conn1's 200 response arrives in
  two packets: headers only first (`http.stat_code` fires, `code_val=200`), body `"200"`
  second (`file.data` fires, `byte_test` checks `"200" == code_val`). A Conn2 spoiler
  (404 full response, body `"000"`) arrives between the two packets, clobbering
  `code_val=404`. Without cache: 0 alerts. With cache: 1 alert.

- `bug-7801-12`: Missed detection via `byte_math`. Same two-connection structure as
  test 11, but uses `byte_math` (not `byte_extract`) as the producer, independently
  exercising the `DETECT_BYTEMATH` save path. Status `"200"` →
  `byte_math: 200+200=400` (`total_val=400`), body `"400"` → `byte_test: 400==400`.
  Spoiler status `"404"` clobbers `total_val=604`. Without cache: 0 alerts. With cache:
  1 alert.

- `bug-7801-13`: False positive prevention. Inverts the failure mode: Conn1 gets a 404
  response (headers first, `code_val=404`), then body `"200"` — should NOT alert
  (`200 != 404`). Conn2 (200 full response, body `"200"`) arrives between Conn1's two
  packets, clobbering `code_val=200`. Without cache: 2 alerts (Conn1 falsely fires).
  With cache: 1 alert (Conn2 only).

- `bug-7801-14`: Combined `byte_extract` + `byte_math` in the same unidirectional rule
  (unidirectional analog of bidirectional test 04). Both variable slots must survive
  across packets. Status `"200"` → `byte_extract base=200`, `byte_math 200+200=400`
  (`total=400`), body `"400"` → `byte_test: 400==400`. Spoiler status `"404"` clobbers
  both `byte_values[0]=404` (base) and `byte_values[1]=808` (total). Without cache:
  0 alerts. With cache: 1 alert.

## Structure

Each directory contains a Suricata rule, `test.yaml` spec, and either a `gen_pcap.py` script
or an `input.pcap` so `suricata-verify` can run them individually or as part of this suite.
