# nfs4-gss-integrity-write

A fresh NFS flow with a small, complete v4 GETATTR exchange first (the
app layer attaches on the first fully parsed record of each direction),
followed by a v4 COMPOUND request using RPCSEC_GSS integrity
credentials (procedure 0, service 2):

- the RPC record marker claims 8 KiB (two 4 KiB packets, with a pure
  server ACK interleaved so the first 4 KiB is buffered on its own),
- the request carries a GSS integrity envelope
  (length, seqnum, data) wrapping a PUTFH + WRITE compound,
- the WRITE op claims 17 MiB, above the 16 MiB default
  `max-write-size`, but the compound itself is small; the record is
  never completed on the wire.

Before the fix, the request-side partial scanner scanned the raw
envelope: its length field was read as the compound tag length, the
scan stayed incomplete, and the record was buffered toward the
attacker-controlled 31-bit record length (the memory-exhaustion path
of Redmine #8791). The scanner must now unwrap the integrity envelope
the same way the full record path does and reject the oversized WRITE
claim from the first buffered packet: a `write_request_too_large`
anomaly, no `malformed_data`, and no buffering toward the claim.
