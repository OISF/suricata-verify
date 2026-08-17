# nfs4-partial-read-rename

Pins the early size rejection of a partial NFSv4 compound reply whose
leading RENAME succeeded before an oversized READ.

The capture is synthetic: a TCP handshake, a small normal exchange and a
second reply compound `RENAME(status=0, two change_info4); READ(claim
4096)` with `app-layer.protocols.nfs.max-read-size=1024`. The RPC
fragment claims the full 4164-byte record but only a fraction of the
READ data is delivered.

A successful RENAME result carries two change_info4 structs (verifier
before, verifier after and the atomic word each, 40 bytes). The
scanner advances the leading RENAME result over both structs; an
advance consuming only the status word lands inside the first
change_info4, whose first word is misread as the next op tag, the scan
aborts and the oversized READ is never rejected while the reply
buffers toward the claimed (up to 31-bit RPC length) size.

Asserts one `read_response_too_large` logged mid-flow (`pcap_cnt: 11`,
file transaction completed) and no `malformed_data` /
`too_many_transactions`.
