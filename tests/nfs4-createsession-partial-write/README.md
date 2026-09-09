# nfs4-createsession-partial-write

A fresh NFS flow with a small, complete v4 GETATTR exchange first (the
app layer attaches on the first fully parsed record of each direction),
followed by a plain v4 COMPOUND request:

- the RPC record marker claims 8 KiB (two 4 KiB packets, with a pure
  server ACK interleaved so the first 4 KiB is buffered on its own),
- the compound declares 2 ops: CREATE_SESSION first, then a WRITE
  claiming 17 MiB, above the 16 MiB default `max-write-size`,
- the record is never completed on the wire.

Before the fix, the request-side scanner fell back to the regular
parser for the leading CREATE_SESSION, which consumed the remaining
buffer with `rest()`: the WRITE claim was only "seen" once the full
(attacker-declared) RPC record was buffered, preserving the
memory-exhaustion path of Redmine #8791. The CREATE_SESSION op is now
advanced per its exact layout (and the parser no longer swallows the
following ops), so the WRITE claim is visible from the first buffered
packet: a `write_request_too_large` anomaly and no buffering toward
the claim.
