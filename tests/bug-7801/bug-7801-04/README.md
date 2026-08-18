# bug-7801-04: bidirectional byte_extract + byte_math in http.uri -> http.stat_msg

Verify that `byte_math` results derived from `byte_extract` values are correctly cached and restored across direction boundaries.

PCAP: `input.pcap` (HTTP GET to `/math/03/02` with a `200 OK` response).
Rule: `test.rules` — uses `=>` (TXBOTHDIR) to extract `a_val=3` from `"/math/03/..."` in `http.uri`, then `byte_math` reads `02` and computes `sum_val = 2 + 3 = 5`. Uses negated `isdataat:!sum_val,relative` on `http.stat_msg` (toclient) after matching `"O"`.
Direction: `flow:established` with `=>` (bidirectional, crosses toserver -> toclient).
