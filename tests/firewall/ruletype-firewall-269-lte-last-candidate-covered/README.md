# ruletype-firewall-269-lte-last-candidate-covered

The last candidate of the walk has no next rule to peek at, but the per-hook
coverage still decides: while a pending LTE rule at the same hook covers it, the
last rule's no match must not apply the hook's default policy.

## Scenario

* sid:100 is a failing LTE rule at `request_line`;
* sid:101 is the out-of-scope sibling at the same hook, last by sid.

At packet 4 sid:100 is still pending, so sid:101 must not apply the
`request_line` default. The default is applied at packet 6, when sid:100's no
match becomes final.

## Expected

exactly 1 default app policy drop (packet 6, hook `http:request_line`); sid:100
and sid:101 do not alert; flow dropped.
