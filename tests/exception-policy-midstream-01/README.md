# Test

Check that the midstream-policy is properly applied in case it's set to
``pass-flow`` in IPS mode.

# Behavior

We expect to have zero alerts, but see ``http`` events logged, as the flow will
still be inspected.

# Pcap

Pcap is the result of a curl to www.testmyids.com
