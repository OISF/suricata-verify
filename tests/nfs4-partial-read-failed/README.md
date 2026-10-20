# NFSv4 partial READ reply: a failed READ op does not hide the size limit

A first READ request and its small response complete normally. The second
reply's RPC fragment claims a ~4.1 KiB record; the capture contains the
reply compound holding a **failed READ operation** (nonzero status, no
result words) followed by a **successful READ response** claiming 4096
bytes, truncated after 140 bytes of the read data. With
`max-read-size: 1024` the response is oversized.

Per the NFSv4 protocol a conforming server stops executing at the first
failed operation, so a successful op after a failed one can only come
from a non-conforming (or malicious) server. The early-rejection scan
must still walk the remaining operations: before the fix it aborted at
the failed READ, so the later oversized READ was never seen and the
reply buffered toward its claimed record length without
`max-read-size` ever running. After the fix the scan continues past
the failed operation and the reply is rejected as
`read_response_too_large` before its payload is buffered.

The test asserts:

* one `read_response_too_large` applayer anomaly,
* the READ transaction is logged mid-flow (pcap_cnt present) with
  `file_tx` set (the transaction is completed, not left open),
* no `too_many_transactions` and no `malformed_data` events.
