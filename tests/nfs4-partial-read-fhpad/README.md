# nfs4-partial-read-fhpad

Pins the early size rejection of a partial NFSv4 compound reply whose
leading GETFH response carries a file handle whose length is not a
multiple of four.

The capture is synthetic: a TCP handshake, a normal small READ
request/response pair, a second READ request and a reply whose compound
carries a successful GETFH response with a 33-byte handle (3 bytes of
XDR padding) followed by a READ response claiming a 4096-byte data blob
(`app-layer.protocols.nfs.max-read-size=1024`). The RPC fragment claims
the full 4200-byte record but the reply packet only delivers through 140
bytes of the READ data.

The scanner delegates the leading GETFH response to the regular parser,
which reads the status, the handle length and the handle bytes but not
the XDR padding of the non-aligned handle. The next op tag therefore
starts 3 bytes early and decodes to opcode zero: before the fix the scan
aborted, the oversized READ was never rejected and the reply kept
buffering toward the claimed (up to 31-bit RPC length) record size. The
scan now consumes the handle's XDR padding (and the record is rejected
mid-flow at the claimed READ length).

Asserts one `read_response_too_large` logged mid-flow (`pcap_cnt: 11`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
