# Test

Check the expected auto behavior, for the master switch for drop-packet and
drop-flow in case of traffic exceptions, in IPS mode.

# Behavior

We expect to have no alerts, and see drop events, includding for the flow. Checks
for the bypassed flow are left to highlight the fact that the indicated exception
policy is overwritten by the master switch.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
