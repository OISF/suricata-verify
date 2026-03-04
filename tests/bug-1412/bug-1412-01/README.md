# bug-1412-01: http.header.raw → file_data cross-buffer byte_extract

PCAP: `test.pcap` (HTTP GET/response pair with a short body).
Rule: `test.rules` — extracts a 2-digit decimal `content_len` from `Content-Length` in `http.header.raw`, then uses `byte_test:1,>,content_len,0,relative` against `file_data` after matching `"test"`.
Direction: `flow:established,to_client` (same-direction, toclient only).
Purpose: reproduce the core cross-buffer scenario where `byte_extract` values were lost when inspection moved from response headers to file data.
