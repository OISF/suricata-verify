# Test

Check that the reject action for the exception policies is minimally functional.
We don't check that the reject packet was created and sent, just that the
packet/flow is dropped.

# Behavior

We expect to only see ``drop`` and ``flow`` events logged, as the flow will be
droped.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
