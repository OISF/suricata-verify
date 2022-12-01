# Test

Check that the proper default exception policy is applied in case the master
switch is disabled and there is no exception policy configured.
stage.

# Behavior

We expect to have ``alert`` and ``http`` events logged, as the flow will
be inspected still.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
