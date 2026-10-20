# nfs4-partial-read-getattr0

Pins the early size rejection of a partial NFSv4 compound reply whose
leading GETATTR result carries an empty attribute list (attr_cnt=0)
before an oversized READ.

The capture is synthetic: a TCP handshake, a normal small READ
request/response pair, a second READ request and a reply whose compound
carries `GETATTR result(status=0, attr_cnt=0); READ result(claim 4096)`
with `app-layer.protocols.nfs.max-read-size=1024`. The RPC fragment
claims the full 4160-byte record but the reply packet only delivers a
fraction of the READ data.

The GETATTR result attribute list is fattr4: attr_cnt + attr_cnt
32-bit words + the attribute fields blob (attrlist4 opaque). Its
length word is present on the wire even when the blob is empty (RFC
7530), and the capture carries the zero-length word. The scanner
advances the leading GETATTR result over the declared count plus that
length word; skipping the (empty) blob word shifts the next op tag
early, the scan aborts and the oversized READ is never rejected while
the reply buffers toward the claimed (up to 31-bit RPC length) size.

Asserts one `read_response_too_large` logged mid-flow (`pcap_cnt: 11`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
