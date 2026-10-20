# Split backward WRITE_ANDX: discard must keep the stream in sync

SMB1: an in-order WRITE_ANDX establishes 4096 bytes on a file. A
WRITE_ANDX to offset 100 (already tracked) is SPLIT across two TCP
segments (600 data bytes, then the remaining 401 + the next command).
The file tracker discards the backward data; its continuation must
still be consumed or the stream desyncs. Checks: no malformed data,
all three WRITE_ANDX commands logged, the file stored with the
in-order writes only, no truncation.
