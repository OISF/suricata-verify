# Repeated first-chunk queue-limit rejections must not accumulate

1100 fresh file handles each send a single out-of-order WRITE larger
than the (lowered) max-write-queue-size, so the first chunk is
rejected before the file tracker is ever opened. The rejected
transaction is completed and its file accounting is balanced
(files_opened zeroed) so the file logger can clean it up. Without
that, every rejected fresh handle keeps a dangling file tx (open file
count with no file) live until flow teardown; past SMB_MAX_TX the
parser stops creating transactions and inspection of the flow stops.
Pins: 1100 write_queue_size_exceeded events, zero
too_many_transactions, zero files opened, no malformed data.
