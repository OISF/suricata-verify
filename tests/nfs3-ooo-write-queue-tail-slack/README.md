# NFSv3 OOO write queue: record slack must not grow the queue

WRITE 2 (out of order) is split across two TCP segments, so
it takes the partial-record path: the args plus 1000 of its 3000 file bytes
arrive first, and the continuation carries the remaining 2000 file bytes plus
2048 bytes of slack the sender left inside the record (the marker claims
5164 bytes for 3116 bytes of args and file data). The slack is not file data
and must not be queued as such.

With `max-write-queue-size=4096` the continuation is the decision point: the
queue holds 1000 (first fragment) + 2000 (continuation) = 3000 file bytes,
under the limit, while counting the record tail would give
1000 + 4048 = 5048, over it. So the cap on the queue add is the tracker's
remaining chunk file bytes; before it, the whole record tail was counted and
the chunk was rejected (an event plus a skip) even though the file data fit.

The capture is its own control: sweeping the limit shows the boundary sits at
the file bytes, not at file bytes + slack.

    max-write-queue-size=2999 -> write_queue_size_exceeded (3000 file bytes)
    max-write-queue-size=3000 -> no event
    max-write-queue-size=4096 -> no event (5048 would fire if slack counted)

Regenerate the capture with `python3 gen.py` (deterministic, no deps).

Checks: no `write_queue_size_exceeded`, `truncated_file_data` or
`malformed_data` anomaly, one WRITE file transaction with 3 chunks whose
`last_xid` is WRITE 3 (xid 0x31000003), and the completed file stored
(1000 x 0x41, 3096 x 0x43, 3000 x 0x42 = 7096 bytes,
sha256 5e9b7e94eb5255facf8f6eb3723b790f1d8eb413c42337530168804af7f000f5).

tshark note: all three WRITE calls dissect normally
(`tshark -r input.pcap -d tcp.port==2049,rpc`), 0 malformed frames.
