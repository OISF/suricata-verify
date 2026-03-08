# Bug 1412 verification suite

This folder documents the regression tests that cover Redmine issue #1412 (cross-buffer `byte_extract`).
Suricata now caches byte keyword values per transaction so later inspections (other buffers or file contexts)
can reuse the extracted integer or string. The tests here reproduce the ET/Pro scenarios that originally
failed and demonstrate the new detection path that saves and restores values before each inspection pass.

## Same-direction test cases (`->`)
- `bug-1412-01`: `http.header.raw` → `file_data` cross-buffer `byte_extract`/`byte_test` (own PCAP).
- `bug-1412-02`: `http.request_line` → `http.header` cross-buffer `byte_extract`/`isdataat` (own PCAP).
- `bug-1412-03`: `http.uri` → `file_data` cross-buffer `byte_extract`/`isdataat` (own PCAP).
- `bug-1412-04`: historical Redmine bundle with original legacy `http_raw_header` rule and PCAP.

## Bidirectional test cases (`=>`)
- `bug-1412-05`: `http.uri` (toserver) → `http.stat_code` (toclient) via `byte_test` (own PCAP).
- `bug-1412-06`: `http.request_body` (toserver) → `http.stat_code` (toclient) via `byte_test` (own PCAP).
- `bug-1412-07`: `http.host` (toserver) → `http.stat_msg` (toclient) via negated `isdataat` (own PCAP).
- `bug-1412-08`: `http.uri` (toserver) `byte_extract` + `byte_math` → `http.stat_msg` (toclient) via negated `isdataat` (own PCAP).

Each directory contains a Suricata rule, `test.yaml` spec, and a `gen_pcap.py` script so
`suricata-verify` can run them individually or as part of this suite. The goal is to show the
per-transaction state cache keeps extracted values alive across buffer transitions and direction
boundaries.
