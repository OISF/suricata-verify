A firewall accept must not cost threat detection its inspection
==============================================================

Two firewall rules and one threat detection rule, on an http2 request. sid 100 is
hooked less-than with no fast pattern, so it is an ordinary candidate and it
accepts the flow. sid 101 is hooked less-than at `response_headers` with a pattern
that is absent from the traffic, so at its own hook it is pending: not in the
candidate list, not decided, and with an iid below the TD rule's because threat
detection loads after the firewall rules.

A walk that reaches a candidate above a pending rule steps through the pending one
first, so that whatever it would have done happens at that point. Stepping through
sid 101 must not evaluate it once the flow already carries an accept: a pending
rule is a firewall rule, and firewall rules are skipped rather than evaluated when
an accept is in effect. If it does run, its accept ends the walk, and every
candidate above it - sid 200 included - loses its inspection for that update.
That is the failure mode of OISF/suricata#16392.

The expectation is therefore both alerts: sid 100 deciding the flow, and sid 200
still alerting nine times. Nine is not a threshold; the pattern sits in the request
body and the stream engine reports it once per DATA segment, so the count is a
property of this pcap.

Be clear about what this case does and does not prove. Measured on a build without
the accept guard, the step-through path is entered 26 times across the whole suite
and in 6 of those the flow already carried an accept; all 26 entries end the walk
immediately. No expectation anywhere in the corpus changes as a result, and this
fixture passes identically with and without the guard, and identically on `main`, where no
pending machinery exists at all - three arms, one verdict, which is the definition
of a guard that cannot yet fail. So it is a tripwire: it
asserts the correct verdict in the shape where the bug would show, so that a future
change which makes the walk-ending observable fails something named instead of
silencing threat detection on a live sensor. The bug is reachable in the mechanism
and currently invisible in the outcomes, which is precisely the combination worth
guarding.
