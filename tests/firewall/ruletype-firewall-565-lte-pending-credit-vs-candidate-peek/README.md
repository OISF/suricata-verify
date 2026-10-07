Pending LTE credit read by a candidate's coverage question
==========================================================

sid 211 is less-than at `request_headers` with a silent fast pattern: the walk
credits its hooks so the states below it stay open. sid 212 is hooked exactly at
the same state, its pattern hits and its second keyword fails, so it is a real
candidate that no-matches.

Those two together exercise the one path where a pending rule's borrowed count can
be seen by somebody else: `DetectFwOtherLteCoversHook()` is called with the *current
candidate's* signature, at three sites in the candidate loop, and none of them is
deciding about a pending rule. If the credit for 211 survived 211 leaving the
running, 212 would be answered by a count for a rule that is no longer in play, and
the state would appear covered when nothing covers it.

Expected outcome is the app default of `http1` firing, as it does without the
pending leg at all: coverage that has to be borrowed should never change what a
fully inspected candidate decides.
