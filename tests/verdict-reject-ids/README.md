# Test and Showcase the Verdict Field in IDS mode

In IDS mode, the verdict field only makes sense with the `reject`
rule action.

# Behavior

As with the `rate_filter` the rule action will change from `alert` to
`reject`, we shall see alerts starting without, then with the `verdict` field.

# Pcap

Comes from the test `threshold-config-rate-filter-reject-hostdst`.
