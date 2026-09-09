# nfs4-malformed-compound-request

A fresh NFS flow with a small, complete v4 GETATTR exchange first (the
app layer attaches on the first fully parsed record of each direction),
followed by a structurally malformed v4 COMPOUND request for a new xid:

- the RPC record marker claims 8 KiB (two 4 KiB packets, with a pure
  server ACK interleaved so the first 4 KiB is buffered on its own),
- the compound declares 100 ops — above the 64-op bound (`ops_cnt` is
  within the first 44 bytes of the record),
- the record is never completed on the wire.

The op count is visible within the first buffered packet, so the
structural error is definitive from the buffered bytes. The request-side
partial scanner must report it as a scan error (not "no oversized op")
and the analyzer must reject the record with a `malformed_data` anomaly
and skip to the record boundary — it must not request buffering toward
the attacker-controlled 31-bit record length (the memory-exhaustion path
of Redmine #8791).
