The state in between must still be decided by its own default
==============================================================

sid 211 is hooked less-than at `request_headers` and its fast pattern is
absent, so it is pending at that state. sid 212 is a live candidate bound
strictly above it, at `request_body`: its pattern hits and its second
keyword fails.

The pairing asks the question a lower hook cannot answer on its own. A
candidate bound above a pending rule wants to know whether anything is
missing for the states in between - and the only correct answer comes from
what is pending *right now*, not from what a rule once needed. If the
coverage 211 required is still on the books after 211 left the running,
the in-between states look covered, 212 never triggers the default, and
the flow is blocked by nothing deciding anything.

Expected outcome is the app default of the in-between state firing, which
is what `main` does with no pending machinery at all. This is therefore a
tripwire, not evidence of a behaviour change: it exists so that a future
accounting shortcut that borrows coverage across a rule's lifetime shows
up as a named failure instead of a silent verdict shift.
