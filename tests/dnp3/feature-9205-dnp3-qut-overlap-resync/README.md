# Redmine feature 9205 — real attack traffic, option on

Same capture as `feature-9205-dnp3-qut-overlap-default`, with
`app-layer.protocols.dnp3.resync-on-bad-start=yes`: the parser skips the tail (`dnp3.bad_start_bytes`,
once), logs the twelve transactions, and marks the first to-client frame parsed after the error with
`dnp3.after_resync` (seven frames follow the error; the event is raised once per error).
