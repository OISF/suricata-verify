## PCAP

This PCAP contains 3 flows. 2 are http and one is TLS. The HTTP flows should
be full passed with no alerts, while the TLS flow should be dropped.

## Current Observations

- Test seems to indicate that Suricata mostly behaves as expected. BUT, although
  we see TLS logged as dropped, the actual flow.action is never set to drop...
