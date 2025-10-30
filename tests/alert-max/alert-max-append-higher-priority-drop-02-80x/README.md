# Test

This is a test for a corner case scenario where the amount of alerts matching
against a single packet > ``packet_alert_max`` and the discarded alert is for
a rule with a ``drop`` action.

Regardless of discarding the alert, Suricata must still enforce its ``drop``
action, if that matched against the packet.

Expected result:

For packet 5 (pcap_cnt 5), alerts for sids 1, 2, 3, and 6.
Alert for sid 4 should be discarded, but the `drop` verdict should still be present.

## Pcap

A single HTTP flow extracted from existing test ``http-protocol-inspect-v2`` pcap

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/5180
