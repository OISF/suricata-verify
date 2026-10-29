# Description

Tests for applying `bsize` as a content depth, from
https://redmine.openinfosecfoundation.org/issues/4226

When a buffer carries a `bsize` with an upper bound (`bsize:N`, `bsize:<N` or a
range), the bound is applied as a `depth` to the content matches in that
buffer, so the pattern matcher and content inspection stop searching at the
bound. An exact `bsize` equal to the length of the only content in the buffer
also flags that content `startswith` and `endswith`.

## bug-4226-01

`--engine-analysis` check that `bsize:10`, `bsize:<26` and `bsize:13<>34` give
depths 10, 26 and 34, that `bsize:>8` gives none, and that only the first three
carry the note naming `bsize` as the source of the depth.

## bug-4226-02

Pcap run on `dns.query` with each `bsize` form (exact, less-than, range,
greater-than) and a partial content. A `bsize` that doesn't match the buffer
length doesn't alert, so the length check still runs next to the depth. A rule
with two `dns.query` instances, each with its own `bsize`, alerts, and so do
rules with the `to_uppercase` and `strip_whitespace` transforms, and a
`bsize:<=` rule.

## bug-4226-03

Pcap run with the depth next to `offset`, `distance`, `within`, a negated
content, `nocase` and a chopped `fast_pattern`. The first three interact with
content limit propagation, since the depth is applied after
`DetectContentPropagateLimits`.

## bug-4226-04

`--engine-analysis` check that an exact `bsize` equal to the length of the only
content flags it `startswith` and `endswith`, and that a shorter content, a
non-exact `bsize` and a buffer with two contents are not flagged.

## bug-4226-05

`--engine-analysis` check of the contents the depth is not applied to: one
whose depth comes from a `byte_extract` variable, a negated one longer than
the bound and a negated one that starts past the bound.

## bug-4226-06

Pcap run with a variable-depth content and a negated fast-pattern content
longer than the bound in `bsize` buffers. The engine starts (the too-long
content gets no depth, so the matcher compiles it) and both rules match.

## bug-4226-07

`--engine-analysis` check of the limits of the depth: the largest bound that
fits (65535) and the first that doesn't, a content that ends at the bound and
one that ends a byte past it, an existing `depth` larger and smaller than the
bound, an `offset` from a variable, a rule with a `bsize` on two buffers, and
a packet buffer (`tcp.hdr`).

## bug-4226-08

`--engine-analysis` check of which lone exact-length contents are flagged
`startswith` and `endswith`: a `nocase` content and one with `offset:0` are, a
negated content and one with a variable depth are not.

## bug-4226-09

Pcap run on HTTP buffers (`http.uri`, `http.host`, `http.user_agent`,
`file.data`, `http.response_body`) with exact, less-than and range `bsize`,
including buffers that are too long for the `bsize`.

## bug-4226-10

Pcap run on `tls.sni` with exact and less-than `bsize`, and a content that is
in the SNI but shorter than it.

## bug-4226-11

The rules of bug-4226-02 under the AC pattern matcher (`mpm-algo: ac`), which
checks the depth itself, so the other matcher code path gives the same
alerts.

## bug-4226-12

Pcap run with `bsize` on a packet buffer (`tcp.hdr`): the 32-byte and 40-byte
TCP headers in `http-connection-toclient` match the rule with the matching
`bsize` and not a smaller one.

## bug-4226-13

`--engine-analysis` check of a rule with two `dns.query` instances, each with
its own `bsize`: each instance's content gets the depth of its own bound. The
same rule matches in bug-4226-02 (sid 8).

## bug-4226-14

`--engine-analysis` check that with more than one `bsize` on a buffer the
smallest upper bound is the depth, in either keyword order, after a lower
bound, and when an exact `bsize` sits next to a range, and that `bsize:<=6`
gives depth 6.

## bug-4226-15

`--engine-analysis` check of the depth on a buffer with a transform: an exact
`bsize` after `to_uppercase` gives the depth and the `startswith` and
`endswith` flags, and `bsize:<20` after `strip_whitespace` gives the depth
only.

## bug-4226-16

Pcap run with `bsize` on `file.data` when the HTTP response body is inspected
in pieces. The body is capped at 30010 bytes and inspected 2000 bytes at a
time, and the content is its last 10 bytes. `bsize:<=`, an exact `bsize` and a
range alert, and a bound shorter than the body doesn't. A probe rule that
needs the start of the body to be missing from the inspected piece also
alerts, which shows the content was found in a later piece.

# PCAP

bug-4226-02, bug-4226-03, bug-4226-06 and bug-4226-11 use the DNS query for
google[.]com (`dns.query` buffer "google.com", 10 bytes) from the
`test-bsize-values-2` capture through the `pcap:` key in their test.yaml.
bug-4226-09 and bug-4226-12 use the HTTP request and response from
`http-connection-toclient`, and bug-4226-10 uses the TLS handshake from
`tls/tls-certs-alert`. bug-4226-16 uses the apt package download from
`http-body-inspect`. The other tests run `--engine-analysis` only and need
no pcap.
