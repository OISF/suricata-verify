# nfs4-partial-write-createblk

Pins the early size rejection of a partial NFSv4 compound request whose
leading CREATE names a block device before an oversized WRITE.

The capture is synthetic: a TCP handshake, a small normal compound and a
second compound `PUTFH; CREATE(ftype=NF4BLK); WRITE(claim 4096)` with
`app-layer.protocols.nfs.max-write-size=1024`. The RPC fragment claims
the full 4204-byte record but only a fraction of it is delivered.

Per RFC 7530 the createhow4 union carries, for block and character
devices (ftype NF4BLK/NF4CHR), an 8-byte nfset4 device number between
the ftype word and the filename, before the fattr4 attribute list. The
scanner advances the leading CREATE over the ftype word, the union
device number when present, the filename string and the attribute list;
an advance missing the nfset4 lands 8 bytes early and the next op tag
read hits the attribute words, the scan aborts and the oversized WRITE
is never rejected while the record buffers toward the claimed (up to
31-bit RPC length) size.

Asserts one `write_request_too_large` logged mid-flow (`pcap_cnt: 7`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
