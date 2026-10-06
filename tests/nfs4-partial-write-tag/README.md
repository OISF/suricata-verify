# NFSv4 partial WRITE: a non-aligned compound tag does not hide the size limit

The RPC fragment claims a ~4.1 KiB record; the capture contains the
request compound with a **one-byte tag** (3 bytes of XDR padding) holding
PUTFH + a WRITE claiming 4096 bytes, truncated after 140 bytes of the
write data. With `max-write-size: 1024` the WRITE is oversized.

The compound tag is an XDR string, so a non-aligned tag is followed by
padding bytes. Before the fix the partial-path scan consumed only
`tag_len` bytes, shifting every later field read 3 bytes early; the
compound then looked like it carried no operations (or garbage), the scan
returned nothing, and the oversized record was buffered toward its
claimed length without the limit ever running. After the fix the tag is
consumed with its padding and the WRITE is rejected as
`write_request_too_large` before its payload is buffered.

The test asserts:

* one `write_request_too_large` applayer anomaly,
* the WRITE transaction is logged mid-flow (pcap_cnt present) with
  `file_tx` set (the transaction is completed, not left open),
* no `too_many_transactions` and no `malformed_data` events.
