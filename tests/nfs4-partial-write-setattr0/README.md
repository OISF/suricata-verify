# nfs4-partial-write-setattr0

Pins the early size rejection of a partial NFSv4 compound request whose
leading SETATTR carries an empty attribute bitmap (attr_cnt=0) before an
oversized WRITE.

The capture is synthetic: a TCP handshake, a small normal compound and a
second compound `PUTFH; SETATTR(stateid, attr_cnt=0); WRITE(claim 4096)`
with `app-layer.protocols.nfs.max-write-size=1024`. The RPC fragment
claims the full record but the second packet only delivers a fraction
of the WRITE data.

The parser's attribute list for SETATTR is bitmap4 + the attribute
fields blob (attrlist4 opaque); its length word is present on the wire
even when the blob is empty, and the capture carries the zero-length
word. The scanner advances the leading SETATTR over the declared count
plus that length word; skipping the (empty) blob word shifts the next
op tag early, the scan aborts and the oversized WRITE is never
rejected while the record buffers toward the claimed (up to 31-bit RPC
length) size.

Asserts one `write_request_too_large` logged mid-flow (`pcap_cnt: 7`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
