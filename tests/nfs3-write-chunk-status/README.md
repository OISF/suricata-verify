# nfs3-write-chunk-status

A v3 WRITE split into two UNSTABLE chunks, in both orders a client can use.

The 9.0 upgrade note promises that a write is logged with the status of the
first reply record that carries one. That only held for a single-chunk write:
the reply path matched a WRITE reply to the file transaction through the xid of
the last chunk sent, so once the second chunk was on the wire a reply to the
first one found nothing, and the status that did land was the last reply seen
rather than the first. A rejected chunk followed by an accepted one therefore
read as a good write, and the `nfs` record could disagree with the `fileinfo`
for the same transaction.

Two flows, one per order, because pipelining (both chunks out before either
reply) is what a Linux client normally does:

    flow A (sport 941, fh 0x51) call 1 (off 0), reply ERR_IO, call 2 (off 64), reply OK
    flow B (sport 942, fh 0x52) call 1, call 2, reply ERR_IO, reply OK

Both must log `ERR_IO` with code 5. The file record of the pipelined flow
keeps the default `OK` and no numeric status: it is written when the file
closes, and with both chunks out before either reply that is the end of the
request side, so no reply has reached the transaction yet. Swapping the two
replies of that flow leaves the file record at `OK` and moves the write record
to `OK`/0, which is the first status seen. That timing is mainline.

The success reply carries `count` 0 because count is what reached stable
storage, and a non-zero count there makes tshark look for reply data no server
sends; the error reply carries the status alone, as RFC 1813 has it.
