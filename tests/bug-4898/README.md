# Bug 4898: Ensure detection events are logged

Redmine: https://redmine.openinfosecfoundation.org/issues/4898
(subtask of [#4482](https://redmine.openinfosecfoundation.org/issues/4482))

When the file decoder or detection engine raised an event via
`DetectEngineSetEvent`, the event landed in `det_ctx->decoder_events` and
then went nowhere.  It wasn't cleared between packets, wasn't copied into
`p->app_layer_events`, and never made it to EVE output.  The fix resets
`det_ctx->decoder_events` at the start of each detection run and
transfers its contents into `p->app_layer_events` at cleanup, so events
appear as EVE anomalies regardless of whether any rule matched them.

## Test cases

### bug-4898-01

The scenario the parent bug (#4482) doesn't cover: an event is raised,
but no `app-layer-event` rule is loaded to match it.  Under the old
code, there would be no trace of the event anywhere in the output.  With
the fix in place, `file.Z_DATA_ERROR` still shows up as an EVE anomaly
purely from the transfer in `DetectRunCleanup` — proving the logging
path is independent of rule matching.

## Coverage notes

The non-leakage aspect of this fix (events from packet N not bleeding
into packet N+1) is already covered by `bug-4482-05`.  The two `detect.*`
events are OOM/overflow conditions and can't be triggered from a pcap.
