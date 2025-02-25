# Test

This is a "fork" of `ips-state-1`, to showcase the `flow.action` update bug.

## PCAP

From `ips-state-1` test.

This PCAP contains 3 flows. 2 are http and one is TLS. The HTTP flows should
be full passed with no alerts, while the TLS flow should be dropped.

## Current Observations

- HTTP flows are passed as expected.

- All the TLS packets appear to be getting dropped, but `flow.action` is never
  set to drop.
