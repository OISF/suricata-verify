# NFSv3 WRITE queue-limit rejection on a split-record continuation

WRITE 2 (out of order, handle B) is split across two TCP segments, so it
takes the partial-record path: the args and the first 2924 of its 8190 data
bytes arrive first, and the continuation carries the rest (5266 bytes) plus
the record's 2-byte XDR pad. The record claim (8264) covers the pad, and the
continuation ends with WRITE 3 in the same segment.

With `max-write-queue-size=4096`, enqueuing the continuation crosses the
limit, so the chunk path rejects it there. The skip must cover the rest of
the file data *and* the padding inside the record claim, or the parser chews
on the pad and WRITE 3 desyncs.

Regenerate the capture with `python3 gen.py` (scapy, deterministic).

Checks: one `write_queue_size_exceeded` on the second transaction, no
malformed data, the WRITE 3 transaction logged, and both intact files stored
(handle A: 4000 x 0x44, handle C: 100 x 0x45). WRITE 2's own file is not
stored: its record is rejected.

tshark note: all three WRITE calls dissect normally (`tshark -r input.pcap
-d tcp.port==2049,rpc`); WRITE 2's pad is inside its record claim, so the
next record starts where the marker says.
