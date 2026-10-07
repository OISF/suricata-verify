Pending LTE rule resolves, then a higher candidate decides the state
====================================================================

Two rules: sid 211 is hooked less-than at `request_headers` with a fast pattern
that is absent, so it is pending at that state; sid 212 is hooked exactly at
`request_line`, its pattern hits and its second keyword fails, so it is a real
candidate that no-matches.

The point of the pairing is the ordering inside one walk. The candidate loop
reaches a rule with an id above the pending one, walks the pending chain to its
end, and then continues with a live candidate. If the "defaults must wait"
decision were taken once at walk start and never revisited, the walk would keep
deferring a policy for a rule that has since been decided. This test pins that
the app default of the state still fires.

Same fixture family as ruletype-firewall-561; the difference is the second rule,
which is what turns a latent over-claim into a decision.
