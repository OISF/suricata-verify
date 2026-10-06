# bug-7801-03: bidirectional http.host → http.stat_msg

PCAP: `input.pcap` (HTTP GET with `Host: len08.example.com` and a `200 OK` response).
Rule: `test.rules` — uses `=>` (TXBOTHDIR) to extract a 2-digit decimal `host_val` from after `"len"` in `http.host` (toserver), then uses negated `isdataat:!host_val,relative` on `http.stat_msg` (toclient) after matching `"O"`.
Direction: `flow:established` with `=>` (bidirectional, crosses toserver → toclient).
Purpose: verify that `byte_extract` values from the Host header cross direction boundaries into the response status message, using negated `isdataat` to confirm fewer bytes remain than the extracted value.
