# NFSv3 READDIRPLUS: a partial metadata reply is bounded by max-metadata-size

Sub-test A of the pair (see
tests/nfs3-readdirplus-partial-metadata-over-read-limit-skip for sub-test B,
which shares this capture): the v3 READDIRPLUS reply (161 entries, record
claim 12284 bytes) arrives split across two TCP segments, so the
partial-record path decides whether to buffer it or skip it. The follow-up
is ACCESS (not GETATTR: v3 GETATTR txs are filtered from EVE) on entry042's
file handle.

`max-read-size=8192` is far below the record, and `max-metadata-size` is left
at its default: a partial metadata reply is bounded by the metadata knob, not
by the read knob, so the reply is buffered to its record boundary, parsed,
and the handle->name mapping reaches the namemap. Before the fix the bound
was `max-read-size`, so the segmented reply was skipped and the ACCESS
carried no filename.

Regenerate: `python3 gen.py` (deterministic, no deps; writes input.pcap).

Checks: the ACCESS response event carries `nfs.filename: entry042`, the
READDIRPLUS transaction is logged with status OK, and no malformed data.

Verified against the rebuilt engine, with the knobs isolated:

    max-read-size=64,    max-metadata-size default -> filename entry042
    max-read-size=32MiB, max-metadata-size=1024    -> filename ""

tshark note: all four RPC calls/replies dissect normally
(`tshark -r input.pcap -d tcp.port==2049,rpc`), 0 malformed frames.
