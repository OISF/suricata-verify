# Test

This is a test for a corner case scenario where the amount of alerts matching
against a single packet is bigger than ``packet_alert_max`` and the discarded
alert is for a rule with a ``drop`` action.

Regardless of discarding the alert, Suricata must still enforce its ``drop``
action, if that matched against the packet.

This test is also particular as it only has one packet.

Expected result:

Alerts for sids 1, 2, 3 and 4. Alert for sid 5 should be discarded, but the `drop`
verdict should still be present.

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/5180
