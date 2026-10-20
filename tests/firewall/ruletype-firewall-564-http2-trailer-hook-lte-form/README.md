# ruletype-firewall-564-http2-trailer-hook-lte-form

A firewall rule using the `<state` (LTE) form with a bound above the state where
its buffer completes is refused at load, exactly like the exact-hook form in
`ruletype-firewall-562-http2-trailer-hook-header-buffer`.

An LTE rule is built once per state up to its bound, so its copy for the buffer's
own state does decide - `http2:stream:<request_trailers` with `http.header` used
to alert where the header block ends. It is refused anyway: a firewall rule must
be evaluated at its hook, and holding the LTE form to a lower standard than the
exact form would leave two rules with the same buffer and the same decision
point behaving differently depending on how the hook is spelled.

`ruletype-firewall-239-lte-http1-raw-header-definitive` covers the LTE form that
does load, bounded at the state where its buffer completes.
