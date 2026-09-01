# nfs3-ooo-gap-inside-chunk

Pins the NFS OOO gap backstop for the case where a TCP gap lands **inside
an active file chunk** and the file tracker fully consumes it.

The capture is synthetic: a TCP handshake followed by 1041 sequential
NFSv3 READ calls (8 KiB each, offsets starting at 1). The reply to the
first read is split: only its first 4096 bytes arrive. The parser takes
the partial-READ fast path, enqueues the received data as an out-of-order
chunk and keeps the rest of the record as an in-progress chunk. The rest
of that record is then missing from the stream (a true TCP gap of exactly
the chunk's remaining size, declared by the client's ACK), so the gap
handler feeds the whole gap to the file tracker, which fully consumes it
and completes the chunk.

Because the file cursor never advances (the first read starts at offset
1), every subsequent reply lands out of order in the FileTransferTracker's
chunk map. With the queue limits disabled
(max-read-queue-size/cnt = 0), the OOO chunk count climbs past the 1024
hard backstop. The backstop only runs on a session tagged as gapped, so
it fires only if the gap handler tags the session as gapped **even when
the file tracker fully consumed the gap**.

Pre-fix (origin/main), the NFS gap handler tagged the session unconditionally,
but the NFS path had no OOO gap backstop at all: nothing truncated the file
or logged an event, and the OOO chunk queue grew unbounded (memory only).
(The "fully consumed gap is not tagged" behavior belongs to the SMB gap
handler, which returns early on `consumed2 == new_gap_size` in
origin/main `rust/src/smb/smb.rs`; it is not the NFS pre-fix behavior.)
The branch's backstop runs on the tagged session, caps the OOO queue at the
operator limit (or the 1024 hard cap when the limit is disabled), truncates
the file and logs `truncated_file_data`; the gap handler must keep tagging
the session **even when the file tracker fully consumed the gap**, which is
what this test pins.

Note: `stream.reassembly.depth` is raised because the gapped stream's
out-of-order data is buffered by the TCP reassembler before the app
consumes it; the 1 MiB default depth would cut the stream short.
