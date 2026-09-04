# NFSv3 OOO backward chunks (retransmissions)

1100 WRITE records retransmit one byte at each offset 0..1099 of a file
whose tracker cursor is already at offset 2000, after a gapped WRITE.
Retransmissions of an already tracked region are never flushed from the
OOO queue, so the tracker discards them instead of queueing them; queue
them and they bypass the queue limits (the offset is not "OOO" in the
offset > tracked sense) and grow the queue past the 1024-entry backstop,
which truncates the file in the gapped stream.

Checks: no truncated_file_data, no malformed data, the final WRITE
transaction (xid 1103) is logged (parser in sync) and the new file is
stored intact.
