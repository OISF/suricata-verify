# ruletype-firewall-275-lte-first-state-tls-rejected

`tls:<client_started` is the auto-accept (`<hook`) form at the protocol's first
to-server state. There are no prior states to cover, so the rule can never mean
anything and `DetectFirewallRuleValidate` rejects it at load - fatal under
`--init-errors-fatal`, which is how the framework runs Suricata. The test loads
the rule with `-T` and greps the specific error from stderr; 263 covers the
same invariant for http1, this covers the tls state table.
