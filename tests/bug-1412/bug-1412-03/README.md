# bug-1412-03: http.uri → file_data cross-buffer byte_extract

PCAP: `test.pcap` (POST to `/upload/20` with small payload).
Rule: `test.rules` — extracts a 2-digit decimal `data_size` from after `"/upload/"` in `http.uri`, then uses `isdataat:data_size,relative` on `file_data` after matching `"data="`.
Direction: `flow:established,to_server` (the rule mixes toserver URI with `file_data` which inspects the response body).
Purpose: verify a URI-derived value remains visible when the file inspection runs in the response direction.
