PCAP
====

With the changes in how we handle the PacketAlertQueue, we want to
ensure that rules with the `DROP` action will be enforced even when
their respective alerts get discarded.

This test has a limit of one alert configured and two rules, with drop being
the lower priority one, meaning it should be discarded, while the drop action is
still respected.

The stats event in the eve-log will show `detect.alerts_suppressed: 1` 
indicating the suppresed `noalert` rule.

Pcap from https://forum.suricata.io/t/suricata-5-0-1-in-ips-mode/94/14
Test adapted from bug-4663-03 test.
