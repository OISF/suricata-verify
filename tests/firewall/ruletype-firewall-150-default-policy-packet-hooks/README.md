Test that packet.default-policy applies to every packet hook.

The hook `pre-stream` has its built-in policy an `accept:hook`, so
inheriting drop:packet changes the outcome. pre-flow and filter are given
accept:hook of their own, leaving pre-stream as the only hook able to drop.
