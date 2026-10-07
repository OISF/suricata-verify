Pending LTE credit seen by a candidate bound above its hook
===========================================================

sid 211 is a less-than rule bound at `request_headers` whose fast pattern is
silent, so the walk borrows a coverage count on its behalf. sid 212 is a live
candidate bound strictly above that state, at `request_body`: its pattern hits and
its second keyword fails.

This is the pairing where a borrowed count can only be seen by an index-derived
number: the higher candidate asks whether rules are missing for the states in
between, which is a question about hooks below itself. If the credit for 211
outlives 211, the answer is yes when nothing is pending, and the default policy
of the state in between is never applied.

Expected outcome is the app default of `http1` firing at `request_headers`
and neither crafted sid alerting, the same verdict main reaches with no pending
machinery at all. Sibling cases: 561 (pending rule alone), 562 (candidate bound
below the hook), 565 (candidate at the pending rule's own state).
