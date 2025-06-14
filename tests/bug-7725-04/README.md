# Test

Test that in a scenario where a rule inspects traffic in an IP-in-IP tunnel, the
engine will properly generate alerts if this decoding is enabled in the configuration
file, and not set up a new flow for said packets, if this configuration is disabled.

## PCAP

Shared by reporter.

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/7725
