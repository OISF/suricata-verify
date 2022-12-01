# Test

Check the bypass behavior for the Exception policies master switch in IPS
mode in case of traffic exceptions.

# Behavior

We expect to have no alerts, nor drop events, only the flow in bypassed state.
Checks are left to highlight the expected behavior in comparison to other
possible behaviors, with different policies in place.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
