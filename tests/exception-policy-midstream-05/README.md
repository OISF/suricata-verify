# Test

Check that the midstream-policy is properly applied in case it's set to
``bypass`` in IPS mode, when the engine firstly sees the stream during SYNACK
stage.

# Behavior

We expect to have no alerts, but to see ``http`` events logged, as the flow will
be inspected still.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
