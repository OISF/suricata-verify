# nfs3-ooo-read-queue-recovery

Pins the NFS read queue-limit **projection**: an in-order append must
never be rejected, even when the queue is already at the limit.

The capture is synthetic (no gaps): max-read-queue-size = 4096.
Reply 1 (offset 8192, 4096 bytes of 0x31... 0x42) lands out of order
(the file cursor is at 0) and fills the queue exactly to the limit.
Reply 2 (offset 0, 8192 bytes of 0x31) is in order: it writes straight
to the file and drains the queued chunk, bringing the queue back to 0.

A projection based on raw queue occupancy (`in_flight + len > limit`)
rejects reply 2 even though it can only drain the queue. The correct
projection rejects only appends that actually grow the queue:
out-of-order data at a new offset.

Checks: no `read_queue_size_exceeded`, and the file completes as
8192 x 0x31 + 4096 x 0x42 (sha256 checked).
