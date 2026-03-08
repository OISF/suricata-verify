# bug-1412-02: http.request_line → http.header cross-buffer byte_extract

PCAP: `test.pcap` (HTTP GET request with path and headers).
Rule: `test.rules` — extracts a 1-digit decimal `uri_len` from after `"GET /"` in `http.request_line`, then uses `isdataat:uri_len,relative` on `http.header` after matching `"Host"`.
Direction: `flow:established,to_server` (same-direction, toserver only).
Purpose: validate cross-buffer value reuse when extraction comes from the request line and the dependent keyword is a header-relative `isdataat`.
