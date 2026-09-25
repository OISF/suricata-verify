# ruletype-firewall-268-lte-mpm-in-progress-not-retired

An LTE rule whose MPM buffer is incomplete at its hook is not a definitive no
match and must stay in the per-hook coverage counts for the rest of the walk.

## Scenario

* sid:100 is an LTE rule at `request_line` with the marker in the URI, which is
  split over packets 4 and 6; at packet 4 the MPM is still in progress;
* sid:101 is the out-of-scope sibling at the same hook, last by sid.

sid:101's no match at packet 4 must not apply the `request_line` default;
sid:100 matches when the line completes (packet 6) and accepts the flow.

## Expected

sid:100 accepts at packet 6, no default app policy drop, sid:101 does not
alert.
