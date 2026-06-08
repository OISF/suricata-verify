# Description

Tests for the `bsize` optimization from
https://redmine.openinfosecfoundation.org/issues/4226

When a buffer carries a `bsize` with a usable upper bound (`bsize:N`,
`bsize:<N`, or a range), the bound is applied as a `depth` to the content
matches in that buffer, so the engine bounds its search instead of scanning the
whole buffer. This mirrors the existing `dsize` and `urilen` optimizations. The
analyzer reports both the applied optimization and a suggestion to use `bsize`
where a rule pins a buffer to a fixed length the long way.

## bug-4226-01

`--engine-analysis` check that the `bsize` upper bound is applied as a content
`depth` (`bsize:10` -> `depth:10`, `bsize:<26` -> `depth:26`,
`bsize:13<>34` -> `depth:34`) and that `bsize:>8` applies none. Also confirms the
analysis note attributing the `depth` to `bsize` is emitted for the bounded
rules only.

## bug-4226-02

Matching behaviour is preserved across all `bsize` modes (exact, less-than,
range, greater-than) and a partial content. A `bsize` that mismatches the buffer
length does not alert, proving the length check still runs alongside the depth
optimization.

## bug-4226-03

Correctness of the depth application against `offset`, multi-content
`distance`, and negated content -- the cases that interact with content limit
propagation, since the depth is applied after `DetectContentPropagateLimits`.

## bug-4226-04

`--engine-analysis` check that the analyzer suggests `bsize` when a single
content is pinned to the whole buffer with `startswith`/`endswith` (and the
`isdataat:!1,relative` form), and stays quiet when only one end is anchored,
when `bsize` already exists, or for a plain unbounded content.

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

Multiple `bsize` on a buffer (a lower + upper bound forming a range) are
accepted; the rule loads, and engine-analysis suggests collapsing them into a
single `bsize` range.

# PCAP

bug-4226-02 and bug-4226-03 reference the DNS query to google[.]com (`dns.query`
buffer "google.com", 10 bytes) from the `test-bsize-values-2` capture via the
`pcap:` key in their test.yaml.
bug-4226-01, bug-4226-04, bug-4226-05, bug-4226-06 and bug-4226-07 run
`--engine-analysis` only and need no pcap.
