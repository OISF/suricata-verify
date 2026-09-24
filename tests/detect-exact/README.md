# Description

Tests for the `exact` keyword. `exact` is shorthand for a `bsize` equal to the
length of the preceding `content`: the content spans the whole buffer. It is
equivalent to `bsize:<content-length>` and, for a lone content, lets the engine
anchor the match with `startswith`/`endswith` and prefilter on buffer length.

## detect-exact-01 (allowed)

`--engine-analysis` check that `content:"google.com"; exact;` loads and produces
the same `startswith`+`endswith` anchoring as the explicit `bsize:10` form.

## detect-exact-02 (boundary)

Matching against a pcap whose `dns.query` is exactly `google.com` (10 bytes). A
content that fills the buffer alerts; a shorter content -- where the buffer is
longer than the length `exact` implies -- never matches.

## detect-exact-03 (invalid)

Every rule is rejected at load: `exact` with no preceding content, a non-zero
`offset`, a relative `within`, a relative `distance`, and a negated content (the
`exact` guards), plus a multi-content buffer whose other content no longer fits
the pinned length (the bsize length check).

## detect-exact-04 (edge)

Accepted corner cases: an explicit `offset:0` (allowed), a single-byte content,
and `exact` composed with a matching explicit `bsize` (two identical bounds).

## detect-exact-05 (suggestion)

The reverse direction: a single content anchored the long way with
`startswith`/`endswith` triggers the engine-analysis suggestion to use `exact`.

## detect-exact-06 (transform)

`exact` composes with a transform: the content and the length bound it injects
both apply to the transformed buffer, so a length-changing transform
(`strip_whitespace`) still yields the depth + `startswith`/`endswith` anchoring.

## detect-exact-07 (transform suggestion)

An anchored `startswith`/`endswith` content on a transformed buffer still gets
the `exact` suggestion -- the transform no longer suppresses it.

# PCAP

detect-exact-02 references the `google.com` `dns.query` capture from
`test-bsize-values-2` via the `pcap:` key. detect-exact-01, detect-exact-03,
detect-exact-04, detect-exact-05, detect-exact-06 and detect-exact-07 run
`--engine-analysis` only and need no pcap.
