# bug-7801-01: bidirectional http.uri → http.stat_code

PCAP: `input.pcap` (HTTP GET to `/data/05/index.html` with a `200 OK` response).
Rule: `test.rules` — uses `=>` (TXBOTHDIR) to extract a 2-digit decimal `uri_val` from after `"/data/"` in `http.uri` (toserver), then uses `byte_test:1,>,uri_val,0,relative` on `http.stat_code` (toclient) after matching `"2"`.
Direction: `flow:established` with `=>` (bidirectional, crosses toserver → toclient).
Purpose: verify that `byte_extract` values cached in the toserver direction are restored and usable when inspection moves to a toclient-only buffer (`http.stat_code`).
