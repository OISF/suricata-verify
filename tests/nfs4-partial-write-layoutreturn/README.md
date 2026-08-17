# nfs4-partial-write-layoutreturn

Pins the early size rejection of a partial NFSv4 compound request whose leading LAYOUTRETURN uses the FILE return type before an oversized WRITE.

The capture is synthetic: a TCP handshake, a small normal compound and a
second compound `PUTFH; LAYOUTRETURN(lr_returntype=FILE); WRITE(claim
4096)` with `app-layer.protocols.nfs.max-write-size=1024`. The RPC
fragment claims the full 4204-byte record but only a fraction of it is
delivered.

Per RFC 8881 18.44 the LAYOUTRETURN4args layout is reclaim + layout
type + iomode + the layoutreturn4 union. FILE (1) carries the
lrf offset/length/stateid and the lrf body opaque; FSID (2) and ALL
(3) carry no additional fields. The scanner advances over the union
case as declared; a fixed-layout advance (or one that reads fields
only another case carries) lands the next op tag read inside the
WRITE arguments, the scan aborts and the oversized WRITE is never
rejected while the record buffers toward the claimed (up to 31-bit RPC
length) size.

Asserts one `write_request_too_large` logged mid-flow (`pcap_cnt: 7`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
