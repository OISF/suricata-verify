# nfs4-partial-write-fhpad

Pins the early size rejection of a partial NFSv4 compound request whose
leading PUTFH carries a file handle whose length is not a multiple of
four.

The capture is synthetic: a TCP handshake, a small normal compound
(PUTFH, zero-length handle) and a second compound whose PUTFH carries a
33-byte handle (3 bytes of XDR padding) followed by a WRITE claiming a
4096-byte payload (`app-layer.protocols.nfs.max-write-size=1024`). The
RPC fragment claims the full 4232-byte record but the second packet only
delivers through 140 bytes of the WRITE data.

The scanner walks the compound op by op and delegates the leading PUTFH
to the regular parser, which reads the handle length and the handle
bytes but not the XDR padding that XDR appends to a non-aligned opaque
byte string. The next op tag therefore starts 3 bytes early and decodes
to opcode zero: before the fix the scan aborted, the oversized WRITE
was never rejected and the record kept buffering toward the claimed
(up to 31-bit RPC length) record size. The scan now consumes the
handle's XDR padding (and the record is rejected mid-flow at the
claimed WRITE length).

Asserts one `write_request_too_large` logged mid-flow (`pcap_cnt: 7`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
