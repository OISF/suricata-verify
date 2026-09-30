# ruletype-firewall-273-lte-absent-completion-state

`absent` at a protocol completion state. The NTP `reference_id` buffer is
present in both requests of the fixture, so the `ntp.reference_id; absent` rule
at `ntp:<request_complete` must not match.

The completion state is also where the buffer engine takes its eof decision:
the request_complete state default policy has to be applied at the completion
packet itself (packets 1 and 3), not deferred to the packet default policy.

## Expected

* no `sid:100` alert;
* one `firewall default app policy` drop at packet 1 and one at packet 3, both
  `to_server`;
* both flows dropped and alerted.
