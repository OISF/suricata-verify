# nfs4-partial-write-getattr0

Pins the early size rejection of a partial NFSv4 compound request whose
leading GETATTR carries an empty attribute bitmap (attr_cnt=0) before an
oversized WRITE.

The capture is synthetic: a TCP handshake, a small normal compound and a
second compound `PUTFH; GETATTR(attr_cnt=0); WRITE(claim 4096)` with
`app-layer.protocols.nfs.max-write-size=1024`. The RPC fragment claims
the full 4204-byte record but the second packet only delivers a
fraction of the WRITE data.

The GETATTR request carries a bitmap4 (attr_cnt + attr_cnt 32-bit
words, no fields blob). For attr_cnt=0 the wire carries exactly the
count word. The scanner advances the leading GETATTR over exactly that
declared count; a miscount (e.g. reading a phantom bitmap word) shifts
the next op tag into the bitmap words or the WRITE tag, the scan
aborts and the oversized WRITE is never rejected while the record
buffers toward the claimed (up to 31-bit RPC length) size.

Asserts one `write_request_too_large` logged mid-flow (`pcap_cnt: 7`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
