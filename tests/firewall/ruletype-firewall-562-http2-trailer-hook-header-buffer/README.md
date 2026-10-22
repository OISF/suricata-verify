# ruletype-firewall-562-http2-trailer-hook-header-buffer

A firewall rule hooked at the HTTP/2 trailer state that matches `http.header`, a
buffer completing one state earlier, is refused while the ruleset loads.

A firewall rule is only evaluated at its hook: the engine runs it once, at the
state named in the rule, and never at an earlier one. `http.header` is complete
by the time the stream tx reaches `http2:stream:request_trailers`, but the header
engine has already run at `request_headers` and is not run again at the hook, so
nothing inspects the buffer there and the rule could never match.
Rather than load a rule that can only ever fail, the engine reports

    buffer http_header completes in state N, before the hooked state M

and exits with an error, which is what this test asserts (`exit-code: 1` plus a
grep of the message in `stderr`).

Two combinations are supported and covered elsewhere:

- the `<state` (LTE) form, `http2:stream:<request_trailers`, which is built per
  state up to the bound, so `http.header` is decided at the state where it
  completes - see `ruletype-firewall-564-http2-trailer-hook-lte-form`;
- a buffer that completes at the hook itself, `http.trailer` at
  `http2:stream:request_trailers` - see `ruletype-firewall-563-http2-trailer-hook-no-match`.

Threat rules (`-S`) are not affected, in either mode: they are evaluated on every
packet, so the buffer/hook pairing carries no constraint there. That case is
pinned by sid 11 in `tests/http2-trailer/test.rules`, which keeps `http.header`
behind the exact trailer hook.
