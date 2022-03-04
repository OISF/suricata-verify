# Test

Check that Suricata properly matches on signatures with method or cookie
modifiers passed to pcre, including cases with negated pcre and relative
modifiers.

This test is based on Suricata unit tests adapted to SV.

## Ticket

Redmine ticket https://redmine.openinfosecfoundation.org/issues/6147

## Pcap

Crafted with Scapy based on buffers present in the original unit tests.
