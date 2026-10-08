# Description

Tests for the `bsize` optimization from
https://redmine.openinfosecfoundation.org/issues/4226

When a buffer carries a `bsize` with a usable upper bound (`bsize:N`,
`bsize:<N`, or a range), the bound is applied as a `depth` to the content
matches in that buffer, so the engine bounds its search instead of scanning the
whole buffer. This mirrors the existing `dsize` and `urilen` optimizations. The
analyzer notes where it applied the depth, and suggests `exact` where a single
content already has both `startswith` and `endswith`.

## bug-4226-01

`--engine-analysis` check that the `bsize` upper bound is applied as a content
`depth` (`bsize:10` -> `depth:10`, `bsize:<26` -> `depth:26`,
`bsize:13<>34` -> `depth:34`) and that `bsize:>8` applies none. Also confirms the
analysis note attributing the `depth` to `bsize` is emitted for the bounded
rules only.

## bug-4226-02

Matching behavior is preserved across all `bsize` modes (exact, less-than,
range, greater-than) and a partial content. A `bsize` that mismatches the buffer
length does not alert, proving the length check still runs alongside the depth
optimization.

## bug-4226-03

Correctness of the depth application against `offset`, multi-content
`distance` and `within`, negated content, `nocase` and a chopped
`fast_pattern`. The first three interact with content limit propagation, since
the depth is applied after `DetectContentPropagateLimits`.

## bug-4226-04

`--engine-analysis` check that the analyzer suggests `exact` when a single
content has both `startswith` and `endswith` (including the
`isdataat:!1,relative` form), and stays quiet when only one of them is set,
when `bsize` already exists, for a content with neither, or for a negated
content. The suggestion appears once per rule.

## bug-4226-05

A buffer may carry more than one `bsize`; the tightest (smallest) bound
applies. A content longer than that tightest bound can never match, so the
signature is rejected at load -- in either keyword order.

## bug-4226-06

An exact `bsize` equal to a lone content's length means the content fills the
buffer, so it is marked `startswith`+`endswith`. `--engine-analysis` confirms
the marking happens for that case and not for a shorter content, a non-exact
`bsize`, or a buffer with more than one content.

## bug-4226-07

Multiple `bsize` on a buffer (a lower + upper bound forming a range, written
with `>`/`<` or with `>=`/`<=`) are accepted; the rules load, and
engine-analysis suggests collapsing them into a single `bsize` range.

## bug-4226-08

Multiple `bsize` on a buffer whose bounds share no satisfiable length are
rejected at load: two differing exact `bsize` values, and a lower bound above
an upper bound, in either keyword order. It also has the sets one step past
the valid ones in bug-4226-13, such as `bsize:>9; bsize:<10`.

## bug-4226-09

Same-direction bounds (two upper or two lower `bsize`) are accepted but are not
suggested as a range, and neither is a range next to an exact `bsize`. The
range suggestion needs a lower-bound and an upper-bound `bsize` (compare
bug-4226-07).

## bug-4226-10

`--engine-analysis` check of the contents the depth is not applied to: one
whose depth comes from a `byte_extract` variable, one longer than the bound and
one that starts past the bound. Also checks that `bsize:<=N` gives a depth.

## bug-4226-11

Pcap run with a variable-depth content and a content longer than the bound in
`bsize` buffers. The engine starts, the variable-depth rule matches, and the
rule with the too-long content never matches.

## bug-4226-12

`--engine-analysis` check of the limits of the depth: the largest bound that
fits (65535) and the first that doesn't, a content that ends at the bound and
one that ends a byte past it, an existing `depth` larger and smaller than the
bound, an `offset` from a variable, a rule with a `bsize` on two buffers, and
a packet buffer (`tcp.hdr`).

## bug-4226-13

`bsize` sets at the edge of having a length that satisfies all keywords: one
valid length left, an exact `bsize` equal to an inclusive bound, and an exact
`bsize` inside a range. All four load. The sets one step past them are
rejected in bug-4226-08.

## bug-4226-14

`--engine-analysis` check of which lone exact-length contents are flagged
`startswith`/`endswith`: a `nocase` content and one with `offset:0` are, a
negated content and one with a variable depth are not.

## bug-4226-15

Pcap run on HTTP buffers (`http.uri`, `http.host`, `http.user_agent`,
`file.data`, `http.response_body`) with exact, less-than and range `bsize`,
including buffers that are too long for the `bsize`.

## bug-4226-16

Pcap run on `tls.sni` with exact and less-than `bsize`, and a content that is
in the SNI but shorter than it.

## bug-4226-17

The rules of bug-4226-02 under the AC pattern matcher (`mpm-algo: ac`), which
enforces the depth itself, so the other matcher code path gives the same
alerts.

## bug-4226-18

Pcap run with `bsize` on a packet buffer (`tcp.hdr`): the 32-byte and 40-byte
TCP headers in `http-connection-toclient` match the rule with the matching
`bsize` and not a smaller one.

## bug-4226-19

`--engine-analysis` check of a rule with two `dns.query` instances, each with
its own `bsize`: each instance's content gets the depth of its own bound. The
same rule matches in bug-4226-02 (sid 8).

# PCAP

bug-4226-02, bug-4226-03, bug-4226-11 and bug-4226-17 reference the DNS query to google[.]com (`dns.query`
buffer "google.com", 10 bytes) from the `test-bsize-values-2` capture via the
`pcap:` key in their test.yaml.
bug-4226-01, bug-4226-04, bug-4226-05, bug-4226-06, bug-4226-07, bug-4226-08
and bug-4226-09 run `--engine-analysis` only and need no pcap.

bug-4226-15 and bug-4226-18 use the HTTP request and response from
`http-connection-toclient`,
and bug-4226-16 uses the TLS handshake from `tls/tls-certs-alert`.
