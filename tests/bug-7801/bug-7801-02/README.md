# bug-7801-02: bidirectional http.request_body → http.stat_code

PCAP: `input.pcap` (HTTP POST with body `size=07&padding=extra` and a `200 OK` response).
Rule: `test.rules` — uses `=>` (TXBOTHDIR) to extract a 2-digit decimal `post_val` from after `"size="` in `http.request_body` (toserver), then uses `byte_test:1,>,post_val,0,relative` on `http.stat_code` (toclient) after matching `"2"`.
Direction: `flow:established` with `=>` (bidirectional, crosses toserver → toclient).
Purpose: verify that `byte_extract` values extracted from the request body persist across direction boundaries into the response status code buffer.
