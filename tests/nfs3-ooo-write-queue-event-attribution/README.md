# nfs3-ooo-write-queue-event-attribution

Pins the **event attribution** of the NFS write queue limit: the
queue event must be attached to the file transaction whose queue
overflowed, not to the newest transaction.

The capture is synthetic: max-write-queue-size = 4096 (count limit
disabled). Three WRITE requests interleave two file handles:

  * handle A (hhash f079d4b8): WRITE 1 (offset 8192, 4096 bytes)
    enqueues an out-of-order chunk that fills the queue to the limit;
  * handle B (hhash 5550c5c4): WRITE 2 (offset 0, 1024 bytes) is in
    order and creates the NEWEST transaction;
  * handle A: WRITE 3 (offset 16384, 4096 bytes) would overflow
    handle A's queue and is rejected.

Pre-fix, the event was raised through the parser state, which attaches
events to the newest transaction: the anomaly's tx_id pointed at
handle B's transaction. With the fix, the event is attached directly
to handle A's transaction (anomaly tx_id == handle A's nfs record id
minus one; the anomaly tx_id is the 0-based app-layer transaction
index, the nfs record id is 1-based).
