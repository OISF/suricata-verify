# Description

Test that engine analysis emits a warning in `rules.json` for IP Only rules
that use `threshold` or `detection_filter` with `track by_flow`, as this is
ineffective for higher counts. This mirrors the existing warning in
`rules_analysis.txt`.

Rules that are not IP Only, or that track by something other than flow,
should not get the warning.
