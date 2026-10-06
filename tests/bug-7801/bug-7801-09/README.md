## Test 09: Original Redmine #1412 rule and pcap

Uses the exact rule and pcap from https://redmine.openinfosecfoundation.org/issues/1412.

**Direction:** Unidirectional (`->`, `flow:to_client`)

**Rule:** `byte_extract` in `http_raw_header` extracts `Content-Length` value (11),
`byte_test` in `file_data` compares 2 bytes after `"test"` against the extracted
value using little-endian comparison.

**Expected:** 1 alert (sid:44412999)
