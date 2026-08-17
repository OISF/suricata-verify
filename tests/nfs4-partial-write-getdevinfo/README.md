# nfs4-partial-write-getdevinfo

Pins the early size rejection of a partial NFSv4 compound request whose
leading GETDEVINFO carries an empty notification bitmap before an
oversized WRITE.

The capture is synthetic: a TCP handshake, a small normal compound and a
second compound `PUTFH; GETDEVINFO(notify bitmap attr_cnt=0); WRITE(claim
4096)` with `app-layer.protocols.nfs.max-write-size=1024`. The RPC
fragment claims the full 4204-byte record but only a fraction of it is
delivered.

The GETDEVINFO request arguments are a 16-byte device id, the layout
type and maxcount words, and the notification bitmap (a bitmap4: count
word + count words). For an empty bitmap the wire carries exactly 28
argument bytes. The scanner advances the leading GETDEVINFO over the
declared bitmap length; a fixed 32-byte advance (or any other
miscount) lands the next op tag read inside the WRITE arguments, the
scan aborts and the oversized WRITE is never rejected while the record
buffers toward the claimed (up to 31-bit RPC length) size.

Asserts one `write_request_too_large` logged mid-flow (`pcap_cnt: 7`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
