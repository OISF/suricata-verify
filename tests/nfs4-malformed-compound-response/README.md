# nfs4-malformed-compound-response

A fresh NFS flow with two small, complete v4 GETATTR exchanges first (the
app layer attaches on the first fully parsed record of each direction),
followed by a structurally malformed v4 COMPOUND reply for the second
request's xid:

- the reply's RPC record marker claims 8 KiB (two 4 KiB packets),
- the compound declares 100 ops — above the 64-op bound (visible within
  the first 44 bytes of the record),
- the record is never completed on the wire.

The op count is visible within the first buffered packet, so the
structural error is definitive from the buffered bytes. The reply-side
partial scanner must report it as a scan error (not "no oversized op")
and the analyzer must reject the record with a `malformed_data` anomaly
and skip to the record boundary — it must not request buffering toward
the attacker-controlled 31-bit record length (the memory-exhaustion path
of Redmine #8791).
