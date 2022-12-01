# Test

Check that the Exception Policy is properly applied in case it's set to
``bypass`` in IDS mode, when the engine firstly sees the stream during
SYNACK stage.

# Behavior

We expect to have no events other than ``flow``, with an indication that it was
bypassed.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
