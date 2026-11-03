A match at a higher hook masks a rule still pending at a lower hook.

Rules:

- `sid 110`: `accept:flow,alert`, hooked at `http1:<request_headers>` (hook 2),
  matching on `http.host` `www.example.com`
- `sid 113`: `accept:flow,alert`, hooked at `http1:<request_started>` (hook 0),
  matching a raw content that never appears in the flow

The pcap is the shared LTE fixture `../lte-matrix-data/http1.pcap`; it sends the request in 5 data packets; the header block terminates at
packet 10, which is the packet that completes hook 2 (the transaction moves to
`request_body`). A rule hooked at state N inspects the buffer of every state
below N, so `sid 110` covers `sid 113`: its match decides the flow, and the
non-match of `sid 113` - which only becomes final at the end of the transaction -
must not get to apply the `http1` default policy. Hence: one alert for `sid 110`
at packet 10 with `accept:flow,alert`, flow accepted, and no policy alert
(2201001) for the default policy.

`main` diverges here. Probing `DetectRunTxPreCheckFirewallPolicy()` there shows
that only `sid 113` ever runs - the transaction walk stays at hook 0 while that
rule is pending and never reaches the hook 2 list - so the coverage never
materializes. `sid 113` then concludes at packet 12 (the transaction reaches its
end state) and applies the `http1` default policy: alert 2201001 with
`drop:flow,alert` and the flow dropped, with `sid 110` never inspected. That
makes the flow drop traffic that an explicit rule accepted.
