# Repeated first-chunk queue-limit rejections must not accumulate

1100 fresh handles each send a single out-of-order WRITE larger than
the (lowered) max-write-queue-size, so the first chunk is rejected
before any file is opened. The rejected transaction is completed and
its file accounting balanced (files_opened zeroed) so it can be
cleaned up. Without this, the file logger keeps every dangling
transaction (files_opened with no file) live until flow teardown, the
list grows past NFS_MAX_TX and evictions fire. Pins: 1100
write_queue_size_exceeded events, zero too_many_transactions, zero
files opened, no malformed data.
