# nfs3-ooo-padded-inorder-drain

Pins that an in-order WRITE completing on its XDR padding drains the
out-of-order queue exactly like an unpadded completion.

The capture is synthetic (NFSv3 over TCP, file store forced):

1. WRITE 1 (xid 1): FH_A offset 0, 4000 x 0x44 (in order; tracked
   4000).
2. WRITE 2 (xid 2): FH_A offset 8097 (out of order), 4000 x 0x45,
   complete in one segment (four-byte aligned, no padding) -- queued.
3. WRITE 3 (xid 3): FH_A offset 4000 (in order), count 4097 -- not
   four-byte aligned, so the record carries 3 bytes of XDR padding and
   completes on the padded path, bringing tracked to 8097.

Pre-fix, a completion carrying pending fill skipped the queue drain,
so the chunk queued at 8097 was never flushed and the stored file held
only 8097 bytes. Post-fix the drain runs on the padded completion:
the queued 4000 x 0x45 chunk is flushed and the stored file is
4000 x 0x44 + 4097 x 0x46 + 4000 x 0x45 (12097 bytes).
