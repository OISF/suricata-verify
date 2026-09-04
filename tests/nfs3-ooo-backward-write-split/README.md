# Split backward WRITE: discard must keep the stream in sync

NFSv3: an in-order WRITE establishes 4000 bytes on file A. A WRITE to
offset 100 (already tracked) is SPLIT across two TCP segments (600 data
bytes, then the remaining 401 + 3 XDR padding + the next record). The
file tracker discards the backward (retransmitted) data; its
continuation must still be consumed (payload AND padding) or the stream
desyncs. Checks: no malformed data, the following WRITE (xid 3) is
logged, file A stored with its original 4000 bytes, the follow-up file
stored intact, no truncation.
