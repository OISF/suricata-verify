# NFSv3 WRITE queue-limit rejection on a split-record continuation

WRITE 2 (OOO, fh B) is split across two TCP segments (partial-write fast
path): the first 2920 of its 8190 data bytes are enqueued, just under
max-write-queue-size (4096). The continuation (5270 bytes) arrives as
[5270 data][2 XDR padding][WRITE 3]: enqueuing it crosses the limit, so
the chunk path rejects. The skip must cover the 2 padding bytes as well
as the file data, or the parser chews on the padding and WRITE 3
desyncs.

Checks: one write_queue_size_exceeded on the second transaction, no
malformed data, the WRITE 3 transaction logged, and both intact files
stored (fh A: 4000 x 0x44, fh C: 100 x 0x45).
