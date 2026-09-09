# nfs4-gss-integrity-read

A fresh NFS flow with a small, complete v4 GETATTR exchange first (the
app layer attaches on the first fully parsed record of each direction),
then:

1. a complete, small v4 COMPOUND request (PUTFH + READ) carrying RPCSEC
   GSS integrity credentials (procedure 0, service 2) wrapping the
   compound in an (length, seqnum, data) envelope. The full request
   path unwraps the envelope and records the GSS combination in the
   per-xid request map;
2. the reply for that xid: the RPC record marker claims 8 KiB (two
   4 KiB packets, with a pure client ACK interleaved so the first
   4 KiB is buffered on its own), and carries a GSS integrity envelope
   wrapping a compound with a single READ op claiming 17 MiB, above
   the 16 MiB default `max-read-size`. The record is never completed
   on the wire.

Before the fix, the reply-side partial scanner scanned the raw
envelope and buffered toward the attacker-controlled 31-bit record
length (the memory-exhaustion path of Redmine #8791). The scanner must
now use the xidmap GSS combination to unwrap the integrity envelope
the same way the full record path does and reject the oversized READ
claim from the first buffered packet: a `read_response_too_large`
anomaly and no buffering toward the claim.
