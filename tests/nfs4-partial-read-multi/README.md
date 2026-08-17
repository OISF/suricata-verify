# NFSv4 partial reply: a completed small READ does not hide a later oversized READ

A first READ request and its small response complete normally. The second
reply's RPC fragment claims a ~8.8 KiB record; the capture contains a
PUTFH response, a fully present 513-byte READ response (within the
1024-byte limit, XDR-padded to 516 bytes on the wire) and the header of a
second READ claiming 8192 bytes before the file ends.

Before the fix the partial-path scan stopped at the first successful READ
it found and returned that READ's claimed length, so a within-limit
leading READ masked every later READ in the same compound: the oversized
payload was buffered (toward the claimed record size) before
`max-read-size` was ever enforced. Skipping the first READ also has to
consume its XDR padding; without that the next opcode is read from the
padding and the scan aborts. After the fix completed, within-limit READs
(data plus padding) are skipped, so the second READ is found and the
reply is rejected as `read_response_too_large` before its payload is
buffered.

The test asserts:

* one `read_response_too_large` applayer anomaly,
* the rejected READ transaction is logged mid-flow (pcap_cnt present)
  with `file_tx` set (the transaction is completed, not left open),
* no `too_many_transactions` and no `malformed_data` events.
