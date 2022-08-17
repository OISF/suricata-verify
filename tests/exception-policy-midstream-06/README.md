# Test

Check that the midstream-policy is properly applied in case it's set to
``drop-flow`` in IPS mode, when the stream is first seen by Suricata in ACK
stage.

# Behavior

We expect to only see ``drop`` and ``flow`` events logged, as the flow will be
droped.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
