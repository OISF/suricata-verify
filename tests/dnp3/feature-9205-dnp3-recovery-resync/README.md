# Redmine feature 9205

DNP3 link-layer recovery with `app-layer.protocols.dnp3.resync-on-bad-start`
enabled, on the capture of `feature-9205-dnp3-recovery-default`.

With the option on, octets without a start sequence are skipped and
`dnp3.bad_start_bytes` is set: the request behind them is logged in flow 2
(mid-stream) and in flow 4 (start of flow, through the probing parser), and
both are marked with `dnp3.after_resync`. In flow 6 the start sequence is at
the end of the first segment, with less than a link header behind it: the
probing parser waits for the next segment, then finds the header and the
request is logged and marked. Flows 3 (bad link-header CRC) and 5 (`LENGTH`
below the minimum) behave as with the option off. The baseline flow raises no
event.
