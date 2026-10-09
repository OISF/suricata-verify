LTE rule in scope, fast pattern silent, default policy in play
==============================================================

One firewall rule, hooked less-than at `request_headers`, its fast pattern on
`http.host.raw` and absent from the traffic. The rule is in the flow's scope, so
it is in the running: the MPM does not add it to the candidates, and the walk has
to treat it as pending rather than as decided.

A build without the MPM candidacy work has the rule in the candidate list, sees
it fail on its own buffer and applies the app default policy of the state. This
test pins that the pending path reaches the same outcome: the packet is dropped
by the `drop:flow, alert` default of `http1`, and sid 211 never alerts.

The other direction - a window whose rules are all out of the flow's scope
deferring a policy that should have been applied - is ruletype-firewall-550.

Which leg decides this: the pending-coverage leg of the fast-pattern work.
Measured identical without that leg, so this is a regression guard rather than a
demonstration of a difference.
