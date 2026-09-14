# smb2-ooo-write-queue-cnt

Pins that the SMB2 write queue count limit
(`app-layer.protocols.smb.max-write-queue-cnt: 3`) is enforced for
out-of-order SMB2 WRITE data, on the to-server direction.

The capture is synthetic: a TCP handshake followed by six SMB2 WRITE
request records sharing one file GUID (no negotiate in the capture: the
first WRITE opens the file transaction by GUID).

- w1 (mid 1) offset 0: in order (tracked 100).
- w2 (mid 2) offset 300: out of order (1st queued chunk).
- w3 (mid 3) offset 400: out of order (2nd).
- w4 (mid 4) offset 500: out of order (3rd).
- w5 (mid 5) offset 600: 3 queued + 1 > 3 -- the enqueue is rejected
  with `applayer/smb/write_queue_cnt_exceeded`, the file transaction is
  completed and closed and the record is skipped.
- w6 (mid 6) offset 100: in order after the rejection; it still lands
  in the file (A*100 + E*100), proving the parser stayed in sync.
