# NFSv4 partial READ reply: a non-aligned compound tag does not hide the size limit

A first READ request and its small response complete normally. The second
reply's RPC fragment claims a ~4.1 KiB record; the capture contains the
reply compound with a **one-byte tag** (3 bytes of XDR padding) holding a
PUTFH response + a READ response claiming 4096 bytes, truncated after 140
bytes of the read data. With `max-read-size: 1024` the response is
oversized.

The compound tag is an XDR string, so a non-aligned tag is followed by
padding bytes. Before the fix the partial-path scan consumed only
`tag_len` bytes, shifting every later field read 3 bytes early; the
compound then looked like it carried no operations (or garbage), the scan
returned nothing, and the oversized reply was buffered toward its claimed
length without the limit ever running. After the fix the tag is consumed
with its padding and the reply is rejected as `read_response_too_large`
before its payload is buffered.

The test asserts:

* one `read_response_too_large` applayer anomaly,
* the READ transaction is logged mid-flow (pcap_cnt present) with
  `file_tx` set (the transaction is completed, not left open),
* no `too_many_transactions` and no `malformed_data` events.
