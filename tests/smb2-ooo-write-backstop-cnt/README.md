# smb2-ooo-write-backstop-cnt

Pins the SMB2 out-of-order queue backstop on a **gapless** stream: the
scan has to run whenever a call carries file data, it must not wait for
a stream gap.

The capture is synthetic: a TCP handshake (large advertised window, the
server ACKs every 50 data packets so the 123 KiB to-server stream is not
cut short by window tracking) followed by 1052 SMB2 WRITE request
records sharing one file guid, with `max-write-queue-cnt: 0`:

- w1 (msg 1) offset 0, 100 bytes: in order, opens the file tx
  (tracked 100).
- q2..q1051 (msg 2..1051) offsets 200..1249, 1 byte each: out of order,
  one new queued chunk per record. The 100..200 hole is never filled, so
  nothing drains and the stream never gaps.
- w2 (msg 1052) offset 100, 100 bytes: the first data carrying call
  after the queue passed the hard chunk-count backstop (1024 with the
  limits disabled). The backstop truncates the file and attaches
  `applayer/smb/truncated_file_data` to the affected file transaction;
  w2's data is consumed but not stored.

With the queue limits turned off the per enqueue check never rejects,
so the backstop is the only thing that can bound the queue: the capture
pins that no `write_queue_*_exceeded` event appears, that the
truncation event is there exactly once, and that the stored file is w1
alone (100 x 0x41).

Pre-fix (the backstop was gated on the session having seen a stream gap)
the queue grows unbounded: no truncation event is logged and the stored
file is w1 + w2 + the 1050 drained chunks (1250 bytes), so both filters
fail.
