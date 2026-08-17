# NFSv4 partial reply: a failed compound status does not hide an earlier oversized READ

A first READ request and its small response complete normally. The second
reply's RPC fragment claims a ~4.1 KiB record and carries a nonzero
compound status (10042): the compound's last operation (a CLOSE response)
failed, but the READ response before it succeeded, claiming a 4096-byte
data blob (> `max-read-size` 1024) that is not present before the file
ends.

The compound status reports the error of the last executed operation; the
operations before it may have succeeded and returned data. Before the fix
a nonzero compound status aborted the partial-path scan immediately, so
the oversized successful READ was never rejected and the reply was
buffered toward the claimed length. After the fix the preceding
successful operations are inspected regardless of the compound status and
the reply is rejected as `read_response_too_large` before its payload is
buffered.

The test asserts:

* one `read_response_too_large` applayer anomaly,
* the rejected READ transaction is logged mid-flow (pcap_cnt present)
  with `file_tx` set (the transaction is completed, not left open),
* no `too_many_transactions` and no `malformed_data` events.
