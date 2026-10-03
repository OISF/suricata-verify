# No premature drop while a flow stays pending on a firewall rule

Fail-closed / pending-semantics check for the firewall when a flow dies
while the rule at `dnp3:request_started` is still provisional (no-match not
yet definitive: no `CANT_MATCH`, tx below its end state).

The rule (sid 211) waits for the marker `DNP3ABORTMARK` in the re-assembled
`dnp3.data` buffer (hook `request_started`, progress 0 while the message is
still being reassembled). DNP3 is used because the tx is left *short* by the
parser when the flow dies: after a FIR-only frame the request tx stays at
`request_started` (progress 0), below its end state, and the keyword can
never match any more.

* flow A (49370) sends the full two-frame message (FIR + FIN) with the
  marker split over the frames: the message completes, the rule matches
  (`accept:flow`), no drops;
* flow B (49371) sends only the first frame (FIR, no FIN) and then RSTs:
  while the rule is still pending the packets must be kept accepted (the
  provisional no match suppresses the per-hook default policy AND keeps the
  packet verdict-less-accepted - the fail-closed backstop in
  DetectRunPostRules would otherwise drop the first data packet, a premature
  drop of a still-pending state). The flow-end RST pass applies the default
  app policy for the hook and drops the flow once.

## Expected

* flow A: sid:211 accepts (alert at the marker); no drop;
* flow B: no early drop; the flow-end default app policy drops the flow once
  at the RST packet.

## Related

Redmine #8944 (auto-accept-prior-states / `<hook` handling);
sibling test 258 (the same scenario when the parser completes the tx on
stream close).
