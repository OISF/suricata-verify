# Redmine feature 9205 — long session and split first segment, option on

Same capture as `feature-9205-dnp3-recovery-session-default`, with
`app-layer.protocols.dnp3.resync-on-bad-start=yes`. The long session behaves
as with the option off. In the second flow, protocol detection looks past the
first link header for a start sequence with a valid header CRC, so the request
in the second segment is detected even though the server never answers; the
twelve octets are skipped (`dnp3.bad_start_bytes`) and the request is logged
and marked with `dnp3.policy_divergence`.
