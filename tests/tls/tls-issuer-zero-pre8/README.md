# Test Description

Based on `tests/tls/tls-issuer-zero`, but modified for pre-8 by adding a Lua
TLS rule to exercise certificate info access with an issuer containing a zero.

## PCAP

Uses ../tls-issuer-zero/input.pcap, modified from tls-glupteba/input.pcap to
inject a zero in an issuer.

## Related issues

https://redmine.openinfosecfoundation.org/issues/7887
https://redmine.openinfosecfoundation.org/issues/6286
