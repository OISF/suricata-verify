# Test

Check that the midstream-policy is properly applied in case it's set to
``pass-flow`` in IPS mode.

# Behavior

We expect to have no alerts, but to see ``http`` events logged, as the flow will
be inspected still.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
