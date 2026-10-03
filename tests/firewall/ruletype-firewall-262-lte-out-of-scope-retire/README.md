# ruletype-firewall-262-lte-out-of-scope-retire

An LTE rule that never covered anything (out of scope for the packet) must
not remove coverage contributed by other pending LTE rules when it retires
after its header check fails.

## Scenario

* sid:6 in-scope `<request_body` rule with a streaming no match (pending at
  request_body, covers its own hook and the prior hooks);
* sid:98 the same hook, out of scope for the packet - its header check fails
  and it retires;
* sid:99 in-scope `<request_headers` rule whose keyword no longer matches,
  covered by sid:6 while it resolves;
* sid:100 `http1:request_body` rule matching "BODY-MARKER".

sid:98's retire must not decrement the coverage sid:6 contributed, so sid:99
resolves without the per-hook default and sid:100 matches and accepts.

## Expected

sid:100 accepts the flow at `http:request_body`; no default app policy drop;
sid:6 and sid:99 do not alert.
