# ruletype-firewall-290-lte-mpm-host-ruleset

The operator's LTE ruleset shape (Redmine #9149 note 2): one broad `tcp:all`
session rule plus 500 `accept:flow http1:<request_headers` rules, one per
distinct `http.host` content. Only one host is present in the traffic.

## Scenario

* 501 `<request_headers` rules; all but one (`sid:600`,
  `www.example.com`) have content that is absent from the flow;
* flows A and B send the request line and the headers in a single packet:
  the first detect of the tx happens with the request_headers state and
  buffer available - the common case. At that state the rules' MPM is the
  only prefilter: the candidate list must contain the matching rule only;
* flow C splits the request line over two packets. Its first detect happens
  at request line (before the rules' hook): the pending window. The rules
  are candidates there via the per-state coverage entries, so no default
  policy may fire at the line state; the matching rule resolves once the
  line and headers complete.

`generate-data.py` regenerates `input.pcap` and `firewall.rules`.

## Expected

`sid:600` accepts all three flows at `http:request_headers`; no default app
policy drop; the unmatched rules never alert.
