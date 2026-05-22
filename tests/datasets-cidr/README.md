# CIDR Dataset Tests

This directory contains suricata-verify tests for the `cidr` dataset type. CIDR
datasets store IPv4 and IPv6 CIDR blocks in radix trees and are queried via the
`ip.src` or `ip.dst` sticky buffers using `dataset:isset` or `dataset:isnotset`.

The dataset file format is plain text, one CIDR notation per line (e.g.
`192.168.0.0/16`, `fc00::/7`).

## Test Overview

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

## Shared pcap relationships

```
input-ipv4.pcap (in datasets-cidr-01-ipv4-isset/)
    used by: 01, 02, 03, 04, 08, 10

input-ipv6.pcap (in datasets-cidr-05-ipv6-isset/)
    used by: 05, 06

input-mixed.pcap (in datasets-cidr-07-mixed/)
    used by: 07 only

input-boundary.pcap (in datasets-cidr-09-boundary/)
    used by: 09 only
```
