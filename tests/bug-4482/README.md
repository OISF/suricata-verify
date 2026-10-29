# Bug 4482: Detection events not in rules

Redmine: https://redmine.openinfosecfoundation.org/issues/4482

The file decoder and detection engine define a set of events
(`FILE_DECODER_EVENT_*` and `DETECT_EVENT_*`) that Suricata raises during
detection — for example when SWF decompression hits corrupt zlib data.
Historically there was no way to write a rule that matched these events,
no shipping rules for them, and no test coverage.  This series of tests
covers the fix: the `app-layer-event` keyword now accepts `file.*` prefix
for file decoder events; detect engine events get their own dedicated
`detect-event:` keyword.  Both transfer into EVE output, and shipping
rules exist in `rules/app-layer-events.rules`.

## Test cases

### bug-4482-01

The main happy path.  A corrupt-SWF HTTP response triggers decompression,
the decompressor raises `file.Z_DATA_ERROR`, and both a `file_data`
content rule and an `app-layer-event:file.Z_DATA_ERROR` rule fire.  The
event also shows up as an EVE anomaly.  This is the test that proves the
whole pipeline works end to end.

### bug-4482-02

Rule-loading smoke test for all 13 `app-layer-event:file.*` rules and the
2 `detect-event:` rules.  All 15 rules are loaded against the same pcap,
but with SWF decompression disabled so nothing should fire.  The real
check here isn't the zero-alert count — it's that every rule parses
successfully.  If any of them fail to parse, Suricata exits before the
check even runs.

### bug-4482-03 and bug-4482-04

Same shape as `bug-4482-01`, but targeting `file.INVALID_SWF_VERSION` and
`file.INVALID_SWF_LENGTH` respectively.  Each uses a pcap crafted to hit
that specific decompressor branch.

### bug-4482-05

Two HTTP transactions in a single pcap: the first carries a corrupt SWF,
the second is plain text.  The test asserts that the Z_DATA_ERROR from
the first transaction does not leak into the second — exactly one alert,
exactly one anomaly, and both HTTP transactions are logged.  This guards
the per-packet reset of `det_ctx->decoder_events`.

### bug-4482-06

Rule-loading smoke test for the `detect-event:` keyword specifically.
Loads `detect-event:TOO_MANY_BUFFERS` and `detect-event:POST_MATCH_QUEUE_FAILED`
against the bug-4482-01 pcap.  Neither event fires from replayed traffic
(they require detect-engine resource exhaustion), so 0 alerts is expected.
Suricata reaching the check at all proves the rules parsed and loaded.

## Coverage notes

The 10 remaining `file.*` events (most of the LZMA variants and the
non-data zlib errors) and the two `detect-event:` events are not
exercised by firing alerts here.  They are effectively OOM or overflow
conditions that can't be triggered reliably from a captured pcap.
`bug-4482-02` and `bug-4482-06` prove they all at least parse; the
detection mechanism itself is identical across all events.
