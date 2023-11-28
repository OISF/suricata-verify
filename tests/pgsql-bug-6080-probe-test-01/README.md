# Test Description

The probing function for PGSQL, in some scenarios, could identify any TCP message
sent to the standard PGSQL port - 5432 - as PGSQL traffic, leading to false
positives.

## PCAP

This pcap was created using the Scapy script included in the test directory,
to reproduce a non-shareable traffic capture.

## Related issues

Bug report on Redmine:
https://redmine.openinfosecfoundation.org/issues/6080
