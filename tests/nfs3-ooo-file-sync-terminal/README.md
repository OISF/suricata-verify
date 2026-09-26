# nfs3-ooo-file-sync-terminal

Pins the terminal bookkeeping for an out-of-order FILE_SYNC v3 WRITE. A
terminal (stable=2) WRITE whose chunk offset is beyond the tracked
position truncates the file at the chunk's `newchunk`, so the record tail
is consumed rather than stored and the tracker's `is_done` transition
never happens inside the stream promise. The tx terminal bookkeeping
(`is_last` / `last_xid` / done flags) therefore has to run at parse time,
as the base did; the promise `is_done` arm only closes a tx whose tail is
actually stored (an in-order live chunk).

Before the fix the v3 WRITE path deferred the whole bookkeeping to the
`is_done` arm whenever the record was partial (`file_data < file_len`),
so for the OOO case the tx kept `last=false` / `last_xid=0` until flow
teardown and the EVE `last_xid` was missing.

The capture is synthetic: an in-order 100-byte UNSTABLE v3 WRITE (xid
0x2001) opens the file, then a terminal 512-byte FILE_SYNC WRITE (xid
0x3001) at an offset beyond the gap, split so the first segment carries
only the args (partial-record path, claim 608 >= 512). The second segment
carries the 512-byte tail, which is consumed (the file is truncated), not
stored.
Regenerate: `python3 gen.py` (scapy).

Checks: the file is logged TRUNCATED with only W1's 100 bytes
(sha256 checked), the WRITE tx event carries `last: true` and
`last_xid: 12289` (W2's xid) at parse time, and no `malformed` events
(desync).

tshark note: the WRITE requests dissect normally (V3 WRITE Call with
FH/offset/len/stable). The writeres replies use the simplified 20-byte
layout (verf, count, offset, stable) shared with the other synthetic v3
write tests; tshark flags those 2 reply packets as [Malformed Packet],
which is expected for this generator's convention.
