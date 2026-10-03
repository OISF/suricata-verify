# ruletype-firewall-270-lte-pending-last-candidate-guard

The higher-hook LTE rule (sid:100 at `http1:<request_headers`) is the last
keyword rule for its hook and its host buffer is incomplete while the tx sits
at the request_headers phase, so its verdict is not final. The failing sibling
sid:200 is last by sid at the lower `<request_line` hook.

The request_headers default policy may only land once sid:100 resolves as a no
match at the packet that completes the host value (packet 10). This guards the
ordering shape behind the `-2` non-final return and the coverage check in the
last-candidate peek: `-2` must not run the hook default and the sibling must
not decide the higher hook while sid:100 is pending.

## Expected

* no drops before packet 10, one `firewall default app policy` drop at
  packet 10 with the `http:request_headers` hook (policy alert sid:2201001);
* neither sid:100 nor sid:200 alerts; the flow ends dropped and alerted.
