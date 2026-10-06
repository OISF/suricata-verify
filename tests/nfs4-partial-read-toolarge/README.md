# NFSv4 partial READ response rejected at the claimed size

A first READ request and its small response complete normally. The second
reply's RPC fragment then claims a ~4.2 KiB record, but only ~204 bytes of
the compound are present before the file ends: a leading PUTFH response
followed by the READ response claiming a 4096-byte data blob. The leading
operation matters: the scan must parse it with its regular parser (feeding
the opcode, not the bytes past it) before it can reach the READ. With
`max-read-size: 1024` the response is oversized.

Before the fix the partial-record path only special-cased NFSv3 READ
replies; an NFSv4 COMPOUND reply fell through to the generic incomplete
handling, buffering toward the claimed (up to 31-bit RPC length) record
size without ever running the limit check. After the fix the reply compound
is scanned up to the READ operation's claimed length and the reply is
rejected as `read_response_too_large` before the remainder is buffered.

The test asserts:

* one `read_response_too_large` applayer anomaly,
* the READ transaction is logged mid-flow (pcap_cnt present) with
  `file_tx` set (the transaction is completed, not left open),
* no `too_many_transactions` and no `malformed_data` events.
