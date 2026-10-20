# NFSv3 READDIRPLUS: over the metadata bound the partial reply is skipped

Sub-test B (the control) of the pair with
tests/nfs3-readdirplus-partial-metadata-over-read-limit: it runs the same
capture (referenced through `pcap:`, so the two sub-tests cannot drift
apart), with `max-read-size=8192` as in sub-test A and
`max-metadata-size=1024` added.

The reply record is 12284 bytes, so it is over the metadata bound: the
partial-record path skips it to its record boundary instead of buffering
toward the claim. The entry mappings never reach the namemap, so the
follow-up ACCESS logs with `nfs.filename: ""`.

Together the two sub-tests pin which knob bounds a partial metadata reply:
the metadata one (here) and not the read one (sub-test A parses the same
record with `max-read-size=8192`). Verified against the rebuilt engine with
the knobs isolated: `max-read-size=32MiB` with `max-metadata-size=1024` also
skips, `max-read-size=64` with the metadata default parses.

Checks: the ACCESS response event carries an empty filename, the
READDIRPLUS transaction still completes (the skip lands exactly on the
record boundary, so the next record parses) and no anomaly is raised.
