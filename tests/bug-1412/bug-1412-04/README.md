# bug-1412-05: historical Redmine bundle

PCAP: `test.pcap` (the original capture from the Redmine issue report).
Rule: `test.rules` — the exact rule from Redmine, using legacy `http_raw_header` content modifier syntax with `byte_extract` and `byte_test` into `file_data`.
Direction: `flow:established,to_client` (same-direction, toclient only).
Purpose: preserve and exercise the original community reproduction so Suricata continues to satisfy the historical detection expectations.
Notes: this directory acts as the ground truth reference for the fix.
