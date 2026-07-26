# Description

Tests for the `exact` keyword. `exact` is shorthand for a `bsize` equal to the
length of the preceding `content`: the content spans the whole buffer. It is
equivalent to `bsize:<content-length>`, and a content that is the only one in
the buffer is also flagged `startswith` and `endswith`.

## detect-exact-01 (allowed)

`--engine-analysis` check that `content:"google.com"; exact;` loads and produces
the same `startswith`+`endswith` anchoring as the explicit `bsize:10` form.

## detect-exact-02 (boundary)

Matching against a pcap whose `dns.query` is exactly `google.com` (10 bytes). A
content that fills the buffer alerts, also with `nocase`, as the second of two
contents, and after the `to_uppercase` transform. A shorter content, where the
buffer is longer than the length `exact` implies, never matches.

## detect-exact-03 (invalid)

Every rule is rejected at load: `exact` with no preceding content, a non-zero
`offset`, an `offset` taken from a variable, a relative `within`, a relative
`distance`, a negated content, a content that is in an earlier instance of the
buffer, and use on the raw payload (rejected by `exact` itself), plus a
two-content buffer whose first content is longer than the `bsize` that `exact`
adds (rejected by the bsize length check).

## detect-exact-04 (edge)

Rules that load: an explicit `offset:0`, a single-byte content, and `exact`
next to an equal explicit `bsize`.

## detect-exact-05 (suggestion)

The reverse direction: a single content anchored the long way with
`startswith`/`endswith` triggers the engine-analysis suggestion to use `exact`.

## detect-exact-06 (transform)

`exact` composes with a transform: the content and the length bound it injects
both apply to the transformed buffer, so a length-changing transform
(`strip_whitespace`) still yields the depth + `startswith`/`endswith` anchoring.

## detect-exact-07 (transform suggestion)

An anchored `startswith`/`endswith` content on a transformed buffer still gets
the `exact` suggestion.

## detect-exact-08

Pcap run with `exact` on `http.host` and `http.uri`: a content that fills the
buffer alerts and one that is only part of the host does not. Uses the capture
from `http-connection-toclient`.

## detect-exact-09

`exact` in firewall rules (`accept:hook dns:request_complete`): the rule whose
content fills `dns.query` alerts and the one with a shorter content does not.
Uses the `google.com` capture from `test-bsize-values-2` and the firewall
configuration from `firewall/ruletype-firewall-23-dns-per-hook`.

# PCAP

detect-exact-02 and detect-exact-09 reference the `google.com` `dns.query` capture from
`test-bsize-values-2` via the `pcap:` key. detect-exact-01, detect-exact-03,
detect-exact-04, detect-exact-05, detect-exact-06 and detect-exact-07 run
`--engine-analysis` only and need no pcap.
