# Xbits Keyword Engine Analysis Test

This test verifies the engine analysis output for the `xbits` keyword.

## Purpose

Tests that the `xbits` keyword is properly analyzed and reported in the `rules.json` output when using `--engine-analysis` mode.

## Coverage

This test covers:
- `xbits:set` with different tracking modes (ip_src, ip_dst, ip_pair)
- `xbits:isset` 
- `xbits:isnotset`
- `xbits:unset`
- `xbits:toggle`
- `xbits` with expire values (60s, 300s)
- Multiple xbits in a single rule

The test verifies all four properties exposed by the engine analysis:
- **cmd**: The xbits command (set, isset, isnotset, unset, toggle)
- **name**: The xbit name being tracked
- **track**: The tracking mode (ip_src, ip_dst, ip_pair)
- **expire**: The expiration time in seconds (when specified)

## Reference

Similar to the flowbits engine analysis test, but for the xbits keyword which tracks state across hosts/networks rather than within a single flow.

