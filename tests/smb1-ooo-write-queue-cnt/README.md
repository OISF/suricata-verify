# smb1-ooo-write-queue-cnt

Pins that the SMB1 write-side queue count limit
(`app-layer.protocols.smb.max-write-queue-cnt`) is enforced for
out-of-order WRITE_ANDX data, on the write direction.

The capture is synthetic: a real SMB1 setup (negotiate, session setup,
tree connect, create of \poc.bin) followed by 8192-byte WRITE_ANDX
writes to FID 0x4001, with `max-write-queue-cnt: 3`:

- w1 (mid 0x101) offset 0: in order (tracked 8192).
- w2 (mid 0x102) offset 49152: out of order (1st queued chunk).
- w3 (mid 0x103) offset 57344: out of order (2nd).
- w4 (mid 0x104) offset 65536: out of order (3rd).
- w5 (mid 0x105) offset 73728: out of order; 3 + 1 > 3 -- the enqueue
  is rejected with `applayer/smb/write_queue_cnt_exceeded`, attached
  to the file transaction, and the record's remaining bytes are
  skipped.
- w6 (mid 0x106) offset 8192: in order, after the rejection.

The assertions pin the event, the stored file content (the in-order
writes only: 8192 x 0x41 + 8192 x 0x46, which proves w6 was parsed and
applied after the rejection), the file-transaction log entry, and the
absence of malformed/truncation events.
