# Test

This test [currently] demonstrates Suricata bug 5867: there are false positive
drop events in the eve logs, for packets that triggered higher priority PASS
rules and DROP rules.

In the scenario shown in this test, `PASS` has a higher priority in the action
order (as it's the default), so the packet should trigger the PASS rule first,
so the DROP rule should have no effect. Even though the flow continues, the DROP
events are seeing in the log.

Bug report: https://redmine.openinfosecfoundation.org/issues/5867

# Behavior

This test currently fails, for we should see no DROP events, but we do.

# Pcap

Pcap comes from forum post where bug was reported the first time:
https://forum.suricata.io/t/drop-log-false-positive-records-possible-since-6-0-6/3228

