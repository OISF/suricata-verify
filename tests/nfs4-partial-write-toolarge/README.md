# NFSv4 partial WRITE record rejected at the claimed size

The RPC fragment claims a 4196-byte record, but the capture contains only
240 bytes of the NFSv4 compound (PUTFH + WRITE with a claimed 4096-byte
payload) before the file ends. With `max-write-size: 1024` the WRITE is
oversized.

Before the fix the partial-record path only special-cased NFSv3
WRITE/READ; an NFSv4 COMPOUND fell through to the generic incomplete
handling, which buffers toward the claimed (up to 31-bit RPC length) record
size and never runs the limit check, so nothing is logged and the buffer
grows unboundedly. After the fix the compound is scanned up to the WRITE
operation's claimed length, the record is rejected as
`write_request_too_large` and skipped before the remainder is buffered.

The test asserts:

* one `write_request_too_large` applayer anomaly,
* the WRITE transaction is logged mid-flow (pcap_cnt present) with
  `file_tx` set (the transaction is completed, not left open),
* no `too_many_transactions` and no `malformed_data` events.
