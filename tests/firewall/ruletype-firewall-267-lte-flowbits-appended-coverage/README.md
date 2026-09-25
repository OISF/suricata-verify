# ruletype-firewall-267-lte-flowbits-appended-coverage

A matched `flowbits:set` rule enables an LTE rule through the post-rule flowbits
prefilter, which appends it to the candidate list mid-walk. That appended rule
must enter the per-hook coverage counts, so the failing sibling at the same hook
does not apply its hook's default policy while the appended rule is pending.

## Scenario

* sid:100 matches at `request_line` and sets flowbit `S`;
* sid:103 is the `flowbits:isset,S` LTE rule at `request_headers`, appended by
  the post-rule prefilter after that match;
* sid:101 is the failing sibling at `request_headers`.

sid:101 must not apply the `request_headers` default; sid:103 matches and
accepts the flow at packet 10.

## Expected

sid:100 alerts (packets 4 and 6), sid:103 accepts at packet 10, no default app
policy drop, sid:101 does not alert, flow accepted.
