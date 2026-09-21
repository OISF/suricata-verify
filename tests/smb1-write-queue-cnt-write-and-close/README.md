# smb1-write-queue-cnt-write-and-close

Pins that an SMB1 WRITE_AND_CLOSE whose write chunk is rejected by the
write queue count limit (`app-layer.protocols.smb.max-write-queue-cnt`)
still terminates the file transaction at the close command, and that the
record following the rejected one (skipped remainder) is still parsed.

The capture is synthetic: a real SMB1 setup (negotiate, session setup,
tree connect, create of \poc.bin, FID 0x4001) copied from
smb1-ooo-write-queue-size, followed by 100-byte writes:

- w1 (mid 0x201) WRITE_ANDX offset 0: in order (tracked 100).
- w2 (mid 0x202) WRITE_ANDX offset 192: out of order (queued).
- w3 (mid 0x203) WRITE_AND_CLOSE offset 224: out of order; with the
  configured limit of 1 queued chunk the enqueue is rejected with
  `applayer/smb/write_queue_cnt_exceeded`, the record remainder is
  skipped, and the close still runs and closes the file transaction.
- w4 (mid 0x204) WRITE_ANDX offset 0: the record after the rejected one,
  same FID; it parses and opens a second file transaction.

The assertions pin the queue event on the affected file transaction, the
single CLOSED file record (the in-order write only, which proves the
close ran on the rejected command and the queued chunk was not drained),
the second (truncated) file record proving w4 parsed in sync, and the
absence of malformed/truncation events.
