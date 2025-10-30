# Test

This is a test for a corner case scenario where the amount of alerts matching
against a single packet is higher than ``packet_alert_max`` and the discarded
alert is for a rule with a ``drop`` action.

Regardless of discarding the alert, Suricata must still enforce its ``drop``
action, if that matched against the packet.

Expected result:

We should see one discarded alert, as there isn't enough space in the alert queue
for the rule with the "drop" action, and Suricata should block the traffic from
the matched packet onwards.

Currently:

Suricata 7 will tag the flow for dropping from packet 1. We see alerts for
sids 2, 3, and 5, only for said packet.

## Pcap

A single HTTP flow extracted from existing test ``http-protocol-inspect-v2`` pcap

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/5180
