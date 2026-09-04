# nfs3-ooo-padded-ooo-write-recovery

Pins that a padded out-of-order WRITE chunk that completes on its
continuation does not corrupt subsequent in-order data.

The capture is synthetic (NFSv3 over TCP, file store forced):

1. WRITE 1 (xid 1): FH_A offset 0, 4000 x 0x44 (in order; tracked 4000).
2. WRITE 2 (xid 2): FH_A offset 8096 (out of order), count 4001 -- not
   four-byte aligned, so the record carries 3 bytes of XDR padding.
   The record is split across two segments: segment A carries the first
   1000 data bytes, segment B carries the remaining 3001 data bytes and
   the 3 padding bytes. The OOO chunk therefore completes on the
   padded path of the tracker's update.
3. WRITE 3 (xid 3): FH_A offset 4000 (in order), 4096 x 0x46.

Pre-fix, completing an OOO chunk on the padded path cleared the chunk
size and the pending fill but left the tracker's OOO marker (and its
offset) set. WRITE 3 then arrived at `offset == tracked` and was
appended to the *previous* OOO entry instead of the file, so the stored
file held only the 4000 x 0x44 prefix and the queued data was never
flushed.

Post-fix the chunk completion settles its state whether or not it
carries padding: WRITE 3 is stored in order, tracked reaches 8096 and
the queued 4001 x 0x45 chunk is flushed. The assertions pin the full
file content (4000 x 0x44 + 4096 x 0x46 + 4001 x 0x45), the parsing of
the third record, and the absence of malformed/truncation events.
