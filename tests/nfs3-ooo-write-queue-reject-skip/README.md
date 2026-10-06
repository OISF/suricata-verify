# nfs3-ooo-write-queue-reject-skip

Pins the skip arithmetic of a rejected NFSv3 WRITE record that arrives
as a **partial record**.

The capture is synthetic: max-write-queue-size = 4096 (count limit
disabled). WRITE 1 (offset 8192, 4096 bytes) enqueues an out-of-order
chunk that fills the queue to the limit. WRITE 2 (count 8192,
file_len 7000 -- the XDR data array is shorter than the claimed count)
would overflow the queue and is rejected. Its record is split across
two TCP segments so the reject lands in the partial-write fast path:
the first segment carries 5000 bytes, the second carries the remaining
2076 bytes of the record.

The reject must skip exactly the record's remaining wire bytes
(`prog_data_size - prog_data.len()` == 2076). The old claimed-count
arithmetic (`count - data.len()` == 3268) skips 1192 bytes past the
record boundary into the following record, desyncing the parser
(malformed data, lost transaction, incomplete file).

Checks: exactly one `write_queue_size_exceeded`, no `malformed_data`,
and the in-order WRITE 3 that follows the skipped tail drains the
queued chunk and completes the file (sha256 checked).
