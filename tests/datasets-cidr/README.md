# CIDR Dataset Tests

This directory contains suricata-verify tests for the `cidr` dataset type. CIDR
datasets store IPv4 and IPv6 CIDR blocks in radix trees and are queried via the
`ip.src` or `ip.dst` sticky buffers using `dataset:isset` or `dataset:isnotset`.

The dataset file format is plain text, one CIDR notation per line (e.g.
`192.168.0.0/16`, `fc00::/7`).

## Test Overview

Tests are grouped by what they exercise:

- 01-10 -- basic type behavior (isset/isnotset for IPv4, IPv6, mixed,
  host-exact precision, boundary conditions, empty dataset)
- 11-12 -- set/unset behavior on IPv4
- 13-14, 22-26 -- rejection tests (options that must fail rule load)
- 15, 17-19 -- the `mask` option and its notations
- 16 -- Lua access to a CIDR dataset
- 20-21 -- set/unset behavior on IPv6

### datasets-cidr-01-ipv4-isset

Basic IPv4 isset test. Five DNS packets are sent to 8.8.8.8 with varying source
IPs. The CIDR file `rfc1918.lst` contains the three RFC1918 blocks. Three source
addresses (192.168.1.5, 10.0.0.50, 172.17.0.1) fall within those blocks and
trigger sid:1. The remaining two (1.2.3.4, 203.0.113.1) are public and do not.

Generates: `input-ipv4.pcap` (shared by tests 02, 03, 04, 08, 10)

### datasets-cidr-02-ipv4-isnotset

Inverts test 01. Uses `isnotset` so sid:1 fires for the two public source IPs
(1.2.3.4 and 203.0.113.1) that are not covered by `rfc1918.lst`. Reuses
`../datasets-cidr-01-ipv4-isset/input-ipv4.pcap`.

### datasets-cidr-03-ipv4-dst

Matches on `ip.dst` instead of `ip.src`. All five packets in the shared pcap
go to 8.8.8.8, which falls inside `8.8.0.0/16` as loaded from `google-dns.lst`.
All five packets trigger sid:1. Reuses `../datasets-cidr-01-ipv4-isset/input-ipv4.pcap`.

### datasets-cidr-04-multi-rule

Two rules reference the same dataset simultaneously. Sid:1 uses `ip.src` isset
and fires for the three RFC1918 source addresses. Sid:2 uses `ip.dst` isnotset
and fires for all five packets because 8.8.8.8 is a public address not covered
by the RFC1918 dataset. Total alert count is 8. Reuses the shared ipv4 pcap.

### datasets-cidr-05-ipv6-isset

Basic IPv6 isset test. Four DNS packets carry IPv6 source addresses. The CIDR
file `ula.lst` contains `fc00::/7`, which covers all ULA addresses. Both
`fc00::1` and `fd12:3456::1` fall within `fc00::/7`; `2001:db8::1` and
`fe80::1` do not.

Generates: `input-ipv6.pcap` (shared by test 06)

### datasets-cidr-06-ipv6-isnotset

Inverts test 05. Uses `isnotset` so sid:1 fires for the two non-ULA source
addresses (2001:db8::1 and fe80::1). Reuses
`../datasets-cidr-05-ipv6-isset/input-ipv6.pcap`.

### datasets-cidr-07-mixed

A single CIDR file `mixed.lst` contains both an IPv4 block (`192.168.0.0/16`)
and an IPv6 block (`fc00::/7`). The pcap contains three packets: an IPv4 packet
from 192.168.1.5, an IPv6 packet from fc00::1, and an IPv4 packet from 1.2.3.4.
Only the first two match.

Generates: `input-mixed.pcap`

### datasets-cidr-08-host-exact

Tests `/32` precision. The file `host32.lst` contains only `192.168.1.5/32`.
From the five-packet shared pcap, only the packet sourced from exactly
192.168.1.5 matches. The other two RFC1918 sources (10.0.0.50 and 172.17.0.1)
do not match despite being private addresses. Reuses the shared ipv4 pcap.

### datasets-cidr-09-boundary

Tests the exact boundary of `192.168.0.0/16`. Four packets probe the first
address of the range (192.168.0.0), the last address (192.168.255.255), one
address just above (192.169.0.1), and one address just below (192.167.255.255).
Sid:1 (isset) fires for the two in-range addresses; sid:2 (isnotset) fires for
the two out-of-range addresses.

Generates: `input-boundary.pcap`

### datasets-cidr-10-empty

Tests behavior with an empty CIDR file. The `empty.lst` file contains no
entries. Sid:1 (isset) never fires because no IP can match an empty dataset.
Sid:2 (isnotset) fires for all five packets from the shared ipv4 pcap because
every IP is absent from the empty dataset. Reuses the shared ipv4 pcap.

### datasets-cidr-11-set

Basic `dataset:set` behavior on IPv4. Four packets from two unique sources
(1.2.3.4 and 5.6.7.8, two packets each). Sid:1 fires exactly once per
unique source: the first packet inserts a new /32 entry (`set` returns
match), the second packet finds it already present (`set` returns no
match). Total alert count is 2.

Generates: `input.pcap`

### datasets-cidr-12-unset

Basic `dataset:unset` behavior on IPv4. `host.lst` preloads 1.2.3.4 and
5.6.7.8. Five packets: two from 1.2.3.4, two from 5.6.7.8, one from
9.9.9.9 (never in the set). Sid:1 fires on the first packet from each
preloaded source (the `unset` removes the entry); the second packet from
each source no longer matches. 9.9.9.9 never matches. Total 2 alerts.

Generates: `input.pcap`

### datasets-cidr-13-save-reject

Rule uses the `save` option on a CIDR dataset. Rule load must fail with
`save/state is not supported for CIDR datasets`. Test runs
`--engine-analysis` (no pcap) and greps the log for that exact string;
requires `exit-code: 1`.

### datasets-cidr-14-state-reject

Same shape as 13, using the `state` option instead of `save`. Same
expected error message.

### datasets-cidr-15-mask

`dataset:set,type cidr,mask 24`. Four packets across two /24s: two
packets each from 192.168.1.5 and 192.168.2.1. With mask 24 the /24
prefix (192.168.1.0/24, 192.168.2.0/24) is what gets inserted, so
sid:1 fires exactly once per unique /24. Packets are constructed with
the same 5-tuple within each /24 so autofp routes them to the same
worker, keeping ordering deterministic.

Generates: `input.pcap` (shared by tests 17 and 18)

### datasets-cidr-16-lua

Two rules. Sid:1 is a standard CIDR `isset` against `rfc1918.lst` (via
`cidr.lst`). Sid:2 uses `lua:cidr-check.lua`; the Lua script calls
`dataset:get("rfc1918-cidr")` and returns 1 when the retrieval succeeds.
Uses `--set default-rule-path=.` so the Lua script is found relative to
the test directory rather than the system rules dir. Reuses the shared
`datasets-cidr-01-ipv4-isset/input-ipv4.pcap`.

### datasets-cidr-17-mask-hex-prefix

Hex-prefix form of the mask option: `mask 0x18` (== 24). Same rule and
expected behavior as test 15; reuses that test's `input.pcap`. Confirms
the parser accepts hex prefix lengths and treats them identically to
their decimal form.

### datasets-cidr-18-mask-bitmask

IPv4 bitmask form of the mask option: `mask 0xffffff00` (== /24). Same
rule shape and expected behavior as test 15; reuses that test's
`input.pcap`. Confirms the parser converts an IPv4 dotted-mask numeric
value to its prefix-length equivalent.

### datasets-cidr-19-unset-mask

`dataset:unset,type cidr,mask 24` with `cidr.lst` preloading two /24
prefixes (192.168.1.0/24, 192.168.2.0/24). Four packets across those
two /24s (mirror of test 15's traffic pattern). Sid:1 fires exactly
once per /24 as the `unset` removes the netblock; subsequent packets in
the same /24 no longer match.

Generates: `input.pcap`

### datasets-cidr-20-ipv6-set

IPv6 mirror of test 11. Four packets from two unique IPv6 sources
(fc00::1 and 2001:db8::1, two packets each). Sid:1 fires once per unique
source (the first packet inserts a new /128 entry; the second finds it
already present). Uses a per-test `suricata.yaml` with `ipv6-compress:
yes` so eve.json emits addresses in RFC 5952 compressed form to match
the `src_ip` filters in `test.yaml`.

Generates: `input-ipv6.pcap`

### datasets-cidr-21-ipv6-unset

IPv6 mirror of test 12. `host.lst` preloads fc00::1 and 2001:db8::1.
Five packets: two from fc00::1, two from 2001:db8::1, one from fe80::1
(never in the set). Sid:1 fires on the first packet from each preloaded
source; second packet from each source no longer matches; fe80::1 never
matches. Also uses `ipv6-compress: yes`.

Generates: `input-ipv6.pcap`

### datasets-cidr-22-mask-isset-reject

Rule combines the `mask` option with `isset` on a CIDR dataset. Rule
load must fail with `mask is only supported for CIDR datasets with 'set'
and 'unset' commands`. `--engine-analysis`, no pcap, `exit-code: 1`.

### datasets-cidr-23-mask-out-of-range

Rule uses a non-contiguous IPv4 bitmask (`mask 0x00ff00ff`). Rule load
must fail with `not a contiguous IPv4 netmask`. `--engine-analysis`,
no pcap, `exit-code: 1`.

### datasets-cidr-24-mask-non-cidr-reject

Rule combines the `mask` option with `type ipv4` (a non-CIDR type).
Rule load must fail with `mask is only supported for CIDR datasets`.
`--engine-analysis`, no pcap, `exit-code: 1`.

### datasets-cidr-25-datarep-cidr-reject

Rule uses the `datarep` keyword with `type cidr`. Rule load must fail;
the datarep type parser doesn't accept `cidr`, so the signature is
rejected and the log contains `error parsing signature`.
`--engine-analysis`, no pcap, `exit-code: 1`.

### datasets-cidr-26-mask-zero-reject

Rule uses `mask 0` (which would match every address). Rule load must
fail with `prefix length 0 is not allowed`. `--engine-analysis`, no
pcap, `exit-code: 1`.

## Shared pcap relationships

```
input-ipv4.pcap (in datasets-cidr-01-ipv4-isset/)
    used by: 01, 02, 03, 04, 08, 10, 16

input-ipv6.pcap (in datasets-cidr-05-ipv6-isset/)
    used by: 05, 06

input-mixed.pcap (in datasets-cidr-07-mixed/)
    used by: 07 only

input-boundary.pcap (in datasets-cidr-09-boundary/)
    used by: 09 only

input.pcap (in datasets-cidr-11-set/)
    used by: 11 only

input.pcap (in datasets-cidr-12-unset/)
    used by: 12 only

input.pcap (in datasets-cidr-15-mask/)
    used by: 15, 17, 18

input.pcap (in datasets-cidr-19-unset-mask/)
    used by: 19 only

input-ipv6.pcap (in datasets-cidr-20-ipv6-set/)
    used by: 20 only

input-ipv6.pcap (in datasets-cidr-21-ipv6-unset/)
    used by: 21 only
```

Tests 13, 14, 22, 23, 24, 25, and 26 do not use a pcap; they are
rejection tests that exercise `--engine-analysis` and grep the log.
