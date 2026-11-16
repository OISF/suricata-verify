A pending rule must stop deferring once it is out of the running
================================================================

Two rules at the same state. sid 211 is hooked less-than at
`request_headers` and its fast pattern is absent from the traffic, so the
walk never reaches it: it is pending, and while it is pending the states
below its hook must stay open. sid 212 is hooked exactly at
`request_headers`, its pattern hits and its second keyword fails, so it is
a live candidate that no-matches and asks its own coverage question.

The contract is that a candidate's coverage question is answered only by
rules that are still in play. If the coverage that 211 needed outlives
211 leaving the running, 212 is answered by an account for a rule nobody
is waiting for: the state looks covered, no default is deferred, and no
rule decides it either.

An implementation that tracks pending coverage per rule, per walk or per
state can all fail this in different ways, which is why the expectation is
`pcap_cnt`, `firewall.hook` and sid 212: the verdict, not the bookkeeping.
A build that never defers for a pending rule passes it too, so this is a
guard rather than evidence of a behaviour change.
