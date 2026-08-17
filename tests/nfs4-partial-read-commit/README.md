# nfs4-partial-read-commit

Pins the early size rejection of a partial NFSv4 compound reply whose leading COMMIT result (status + writeverf4) precedes an oversized READ.

The capture is synthetic: a TCP handshake, a small normal exchange and a
second reply compound `COMMIT(status=0); READ(claim 4096)` with
`app-layer.protocols.nfs.max-read-size=1024`. The RPC fragment claims
the full 4164-byte record but only a fraction of the READ data is
delivered.

The COMMIT result carries status + writeverf4 (RFC 8881); the scanner advances over
exactly that. A different advance (e.g. one expecting a structure the
result does not carry) lands the next op tag read misaligned, the scan
aborts and the oversized READ is never rejected while the reply
buffers toward the claimed (up to 31-bit RPC length) size.

Asserts one `read_response_too_large` logged mid-flow (`pcap_cnt: 11`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
