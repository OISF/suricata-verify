# Test Purpose

Verify that an IPv6 hop-by-hop option whose length field runs one byte
past the option area is rejected as `decoder.ipv6.exthdr_invalid_optlen`.

Before the per-option bounds check in `DecodeIPV6ExtHdrs` was corrected,
such an option was accepted and the Router Alert `memcpy` read one byte
past the option area.

## PCAP

Hand-crafted: IPv6 (payload len 8, next header hop-by-hop) carrying an
8 byte hop-by-hop header with three Pad1 options followed by a Router
Alert that declares 2 data bytes while only 1 fits in the 6 byte option
area.
