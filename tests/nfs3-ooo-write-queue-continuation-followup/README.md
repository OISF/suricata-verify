# Continuation-limit rejection: the follow-up's padding must be consumed

NFSv3 with max-write-queue-size 4096: an OOO WRITE (offset 8192, 5000
bytes) is split; its 2000-byte continuation crosses the limit and the
chunk path rejects it (event on the file's tx, tracker truncated, the
transaction stays open). A SPLIT follow-up WRITE on the same handle
(in order, 501 bytes, XDR padding 3) then arrives: on the truncated
tracker its 201-byte continuation must consume the payload AND the
padding, else the following record desyncs. Checks: the queue event is
attributed to the file's own tx (tx_id 0), no malformed data, the
following WRITE (xid 4) is logged, the new file stored intact.
