# Redmine #9194 NFSv3 WRITE XDR padding omitted from continuation accounting

Regression test for https://redmine.openinfosecfoundation.org/issues/9194
(stable backport https://redmine.openinfosecfoundation.org/issues/9195).

## Trigger shape

An NFSv3 WRITE over TCP whose record is large enough for the partial-record
fast path (>= 512 bytes) stores the XDR padding (1-3 bytes for a file length
that is not 4-byte aligned) as tracker `fill_bytes`, but the outer stream
continuation (`ts_chunk_left`) only counts unread *file data*. When a TCP
segment boundary falls on the last file-data byte or inside the padding, the
continuation finishes with pad bytes still owed. The parser then reads the
remaining pad as the start of the next RPC record marker, records
`nfs malformed_data`, returns a fatal error, and NFS inspection stops for the
rest of that flow: the following COMMIT and LOOKUP are never parsed.

Each case is an independent flow (distinct client source port, handle, and file
content). A flow writes a file at offset 0, COMMITs it (which closes an
UNSTABLE file), then does a LOOKUP that must alert. Except for the chunk2
flows (h-k, see below), every file is a single chunk, which avoids the
unrelated complete-WRITE stale-fill-bytes defect that only affects the *next*
chunk of a multi-chunk file.

Pad lengths and split points (file length -> pad): 415->1, 414->2, 413->3. The
last digit of a flow's client port is its pad length.

| group | sports | shape | pads | segment layout |
| --- | --- | --- | --- | --- |
| control | 41001-41003 | unsplit | 1,2,3 | whole WRITE+COMMIT+LOOKUP in one segment |
| a | 42001-42003 | split at pad | 1,2,3 | seg1 ends on the last file byte; pad + next records follow |
| b | 43002-43003 | split inside pad | 2,3 | seg1 ends after exactly one pad byte; rest of pad + next records follow |
| c | 44001-44003 | continuation | 1,2,3 | header+part data \| rest of data ending on the last file byte \| pad + next records |
| d | 45002-45003 | continuation, split pad | 2,3 | like c, but one pad byte rides with the data and the rest arrives later |
| e | 46003 | FILE_SYNC continuation | 3 | shape c with `stable=2` and no COMMIT: the file closes when its data ends while the pad is still owed |
| f | 47003 | split, pad byte by byte | 3 | seg1 ends on the last file byte \| 1st pad byte alone \| 2nd pad byte alone \| last pad byte + next records |
| g | 48001-48003 | continuation, pad alone | 1,2,3 | header+part data \| rest of data ending on the last file byte \| all pad bytes alone \| next records |
| h | 49002 | chunk2 control | 2 | header+part data \| rest of data + pad + second WRITE + next records |
| i | 50002 | chunk2 continuation | 2 | header+part data \| rest of data ending on the last file byte \| pad + second WRITE + next records |
| j | 51002 | chunk2 continuation, split pad | 2 | like i, but one pad byte rides with the data and the other arrives with the second WRITE |
| k | 52002 | chunk2 split at pad | 2 | header + all file data, no pad \| pad + second WRITE + next records |

## Second chunk (chunk2 flows h-k)

The single-chunk flows only prove that the stream stays in sync: their COMMIT
closes the file whatever the file tracker's fill state is. A fix that only
skipped the late pad bytes in the stream would pass those flows, but the
tracker would still owe the pad as `fill_bytes`, and the next chunk of the
same file truncates it (`FileTransferTracker::new_chunk` truncates the file
while the previous chunk has `chunk_left` or `fill_bytes` left). So the chunk2
flows write a first, partial WRITE of 414 bytes (pad 2, UNSTABLE) and, right
after its pad, a complete WRITE of an aligned 512-byte chunk at offset 414 of
the same handle, then COMMIT and LOOKUP. Fixed, the file is `CLOSED` with 926
bytes and the sha256 of both chunks; with a skip-only fix it would be
`TRUNCATED` at 414 bytes while the alert, anomaly, and parser-error checks
still pass. The second chunk is aligned and complete and the first one is
always a partial record, as a complete WRITE with an unaligned length keeps
stale fill bytes on every build. No chunk2 flow has a first delivery that ends
inside the pad: the parser consumes those pad bytes with the rest of that
delivery without passing them to the file tracker, so the second chunk would
be truncated by that known, out-of-scope stale-fill-bytes defect whether or
not this fix is present.

## Fixed expectation

For every flow: the LOOKUP is parsed and alerts (`sid:9194001`,
`nfs_procedure:3`), the WRITE file is `CLOSED` with exactly the file length
(926 bytes for the chunk2 flows) and the sha256 of its data (the pad is not
file data), there is no `malformed_data` anomaly, and
`app_layer.error.nfs_tcp.parser` is 0.

The `fileinfo.sha256` values are pinned per flow in `test.yaml`; the four
control flows (the three single-chunk ones and chunk2 flow h) already produce
them on the vulnerable build, which confirms the expected bytes, including the
concatenation of both chunks.

## Baseline (vulnerable) behavior

On `main` @ 4badfd13f4 the four control flows pass; the 18 split/continuation
flows lose the LOOKUP alert, truncate the file (no sha256; the chunk2 flows at
414 bytes, before the second chunk), and each raises one `malformed_data`
anomaly and one NFS parser error. The FILE_SYNC flow (shape e) additionally
truncates at the seg1 partial-data length because the FILE_SYNC tx is closed
before its continuation data arrives; it fully passes only with the companion
#9196 fix in the same series. The #9196 and #9192 fixes alone do not make the
test pass; it passes once the #9194 fix is applied.

## Regenerate the PCAP

```
./make-pcap.py
```

It writes `input.pcap` in this directory and prints the per-flow table whose
sizes and sha256 values are used in `test.yaml`. Deterministic (fixed MACs,
sequence numbers, and timestamps). New flows are only appended, so the
existing flows stay byte-identical.
