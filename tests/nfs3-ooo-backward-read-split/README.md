# Split backward READ reply: discard must keep the stream in sync

NFSv3: a first READ reply (offset 0, 4000 bytes) stores file A on the
ToClient tracker. A second READ of offset 100 (already tracked) gets a
reply SPLIT across two TCP segments (600 data bytes, then the
remaining 401 + 3 XDR padding). The file tracker discards the backward
(retransmitted) reply data; its continuation must still be consumed
(payload AND padding) or the stream desyncs. Checks: no malformed
data, the following READ (xid 3) is logged, file A stored with its
original 4000 bytes (the retransmission is not applied), the follow-up
read file stored intact, no truncation.
