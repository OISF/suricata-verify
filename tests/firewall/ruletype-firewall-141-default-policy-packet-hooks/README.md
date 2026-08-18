Test that packet.default-policy applies to every packet hook, not just filter.

pre-stream is where this is observable as its built-in policy is accept:hook, so
inheriting drop:packet changes the outcome. pre-flow and filter are given
accept:hook of their own, leaving pre-stream as the only hook able to drop.

The flow event shows the packets got past pre-flow, so the drops happened at
pre-stream. The two rules in firewall.rules exist only to install the pre-flow
and pre-stream hooks, which are skipped entirely when no rule targets them.
