# nfs4-partial-write-layoutreturn-fsid

Pins the early size rejection of a partial NFSv4 compound request whose leading LAYOUTRETURN uses the FSID return type (union void) before an oversized WRITE.

The capture is synthetic: a TCP handshake, a small normal compound and a
second compound `PUTFH; LAYOUTRETURN(lr_returntype=FSID); WRITE(claim
4096)` with `app-layer.protocols.nfs.max-write-size=1024`. The RPC
fragment claims the full 4204-byte record but only a fraction of it is
delivered.

Per RFC 8881 18.44 the LAYOUTRETURN4args layout is reclaim + layout
type + iomode + the layoutreturn4 union. the union is void for FSID: the return-type word is the last
field of the LAYOUTRETURN arguments. An advance reading lrf fields
anyway lands the next op tag read inside the WRITE arguments, the
scan aborts and the oversized WRITE is never rejected while the
record buffers toward the claimed (up to 31-bit RPC length) size.

Asserts one `write_request_too_large` logged mid-flow (`pcap_cnt: 7`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
