# nfs3-ooo-padded-ooo-read-recovery

Response-side twin of nfs3-ooo-padded-ooo-write-recovery: pins that a
padded out-of-order READ reply that completes on its continuation does
not corrupt subsequent in-order replies on the ToClient tracker.

The capture is synthetic (NFSv3 over TCP, file store forced):

1. READ 1 (xid 1): request FH_A offset 0, count 4000; reply 4000 x
   0x44 (in order; tracked 4000).
2. READ 2 (xid 2): request FH_A offset 8096, count 4001 (not
   four-byte aligned -> 3 bytes of XDR padding on the reply). The
   reply is split across two segments: segment A carries the first
   1000 data bytes, segment B carries the remaining 3001 data bytes
   and the 3 padding bytes.
3. READ 3 (xid 3): request FH_A offset 4000, count 4096; reply
   4096 x 0x46 (in order).

Pre-fix, the padded OOO completion left the ToClient tracker's OOO
marker stale, so READ 3's data was appended to the previous OOO entry
instead of the file. Post-fix the read file is stored with all three
regions (4000 x 0x44 + 4096 x 0x46 + 4001 x 0x45).
