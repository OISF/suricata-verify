# nfs4-partial-read-getattr4

Pins the early size rejection of a partial NFSv4 compound reply whose
leading GETATTR result carries a FOUR-word attribute bitmap
(attr_cnt=4) before an oversized READ.

The capture is synthetic: a TCP handshake, a normal small READ
request/response pair, a second READ request and a reply whose compound
carries `GETATTR result(status=0, attr_cnt=4, 4-word bitmap, empty
fields blob); READ result(claim 4096)` with
`app-layer.protocols.nfs.max-read-size=1024`. The RPC fragment claims
the full record but the reply packet only delivers through 140 bytes of
the READ data.

The scanner walks the compound op by op and advances leading ops using
only their declared length fields (attribute bitmap counts, XDR string
lengths) plus XDR padding where the wire carries it. The regular parser
the scan previously delegated to reads at most three bitmap words, so a
four-word bitmap left the advance one word short: the next op tag
decoded to zero, the scan aborted, the oversized READ was never
rejected and the reply kept buffering toward the claimed (up to 31-bit
RPC length) record size.

Asserts one `read_response_too_large` logged mid-flow (`pcap_cnt: 11`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
