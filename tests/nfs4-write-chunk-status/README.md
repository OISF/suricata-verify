# nfs4-write-chunk-status

A v4 UNSTABLE WRITE split over two compounds, both out before either reply.

The reply side reaches a write's file transaction through the xid of the last
chunk, which is the newest one sent, so a reply to an earlier chunk found no
transaction and the status logged was whichever reply landed last. The v4 reply
path now hands the handle to the lookup the way v3 does, and the record
reports the first error any reply carried, so the rejected chunk stays
visible.

The v4 compound's own procedure is COMPOUND for every reply, so the test that
gated this on `xidmap.procedure == NFSPROC4_WRITE` never fired; it keys on the
compound having answered a WRITE op instead.

    xid 0x43000001  PUTFH + WRITE offset 0,   100 bytes  reply NFS4ERR_IO
    xid 0x43000002  PUTFH + WRITE offset 100,  50 bytes  reply OK

The two chunks are one file transaction: the tracker appends past its
high-water mark, so the record says offset 0, size 150. Without the fix that
record says OK with code 0, because only the reply to the newer chunk lands.
