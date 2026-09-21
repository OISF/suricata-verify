# smb2-ooo-write-queue-cnt-split

Pins the SMB2 queue-limit rejection on the *partial* NBSS record path:
the rejected WRITE straddles a TCP segment boundary, so its remainder
skip and the following record's bytes share a segment.

The capture is synthetic: 6 SMB2 WRITE records to one file guid, with
max-write-queue-cnt 3:

- w1 (msg 1) offset 0: in order (tracked 100).
- w2..w4 (msg 2..4) offsets 300..500: out of order (queue 3).
- w5 (msg 5) offset 600, 700 bytes: would add a 4th queued chunk
  (3 + 1 > 3) and is rejected with
  `applayer/smb/write_queue_cnt_exceeded`. Its NBSS record is split
  across two segments: the first carries the SMB2 header, the write
  body and 444 of the 700 data bytes (560 bytes, so the parser takes
  the partial-record path with wr.data.len() < wr.wr_len), the second
  carries the 256-byte remainder plus w6.
- w6 (msg 6) offset 100: in order after the rejection.

The assertions pin the queue event on the file transaction and the
stored file (the 2 in-order writes only), which proves the skipped
remainder of the rejected record did not consume w6's bytes. Pre-fix
(the rejected flag did not scope the trailing file-data promise) the
remainder skip left file_ts_left > 0 and w6's first bytes were eaten as
file data, so the file assertions fail.
