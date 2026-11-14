# nfs3-write-chunk-status

v3 WRITEs that a reply cannot settle on its own: a write split into two
chunks, in the orders a client uses, and two writes to one handle in flight
together.

The 9.0 upgrade note says a record reports the status its replies carried. For
a write in several chunks that is more than one reply, so a rule is needed.
First-wins was not it: the reply path matched a WRITE reply to the file
transaction through the xid of the last chunk sent, so once chunk 2 was on the
wire a reply to chunk 1 found nothing, and a rejected chunk followed by an
accepted one read as a good write. The rule now is the first error any reply
carried, otherwise the first status seen.

    flow A (941, fh 0x51) call 1 (off 0), reply ERR_IO, call 2 (off 64), reply OK
    flow B (942, fh 0x52) call 1, call 2, reply ERR_IO, reply OK
    flow C (943, fh 0x53) call 1, reply OK, call 2, reply ERR_NOSPC
    flow D (944, fh 0x54) call 1, call 2, reply OK, reply ERR_NOSPC
    flow E (945, fh 0x55) call 1 FILE_SYNC (off 0), call 2 UNSTABLE (off 64),
                   reply 1 ERR_IO, reply 2 OK

A to D each log one write record of 128 bytes with the error and its code, and
none of them logs `OK`. B is the order a Linux client normally uses.

Flow E is two transactions rather than two chunks. The FILE_SYNC write is
complete from its request and its record is already out when the reply comes,
so that reply has nothing to land on; what must not happen is for its error to
be reported for the UNSTABLE write, whose own reply accepted it. The flow logs
two write records, the second `OK` at offset 64 with code 0, and no `ERR_IO`.

The file record of flow B keeps the default `OK` and leaves out the numeric
status: it is written when the file closes, and with both chunks out before
either reply that is the end of the request side, so no reply has reached the
transaction yet. The `nfs` record for the same write says `ERR_IO`, which is
the point.

Replies carry `wcc_data` in both the accepted and the failed form, as RFC 1813
has it; leaving it out reads as a malformed packet to tshark even though the
status still decodes. The accepted UNSTABLE reply reports `count` 0, the bytes
that reached stable storage.
