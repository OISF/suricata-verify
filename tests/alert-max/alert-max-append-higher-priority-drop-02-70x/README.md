# Test

This is a test for a corner case scenario where the amount of alerts matching
against a single packet > ``packet_alert_max`` and the discarded alert is for
a rule with a ``drop`` action.

Regardless of discarding the alert, Suricata must still enforce its ``drop``
action, if that matched against the packet.

Expected result:

Suricata 7 will tag the flow for dropping from packet 1. We see alerts for
sids 2, 3, 4 and 5, only for said packet.

There is no alert queue overflow for this specific scenario and Suricata 7.

## Pcap

A single HTTP flow extracted from existing test ``http-protocol-inspect-v2`` pcap

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/5180
