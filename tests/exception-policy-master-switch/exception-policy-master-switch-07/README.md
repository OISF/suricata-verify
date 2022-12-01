# Test

Check that the Exception Policy is properly applied with default configuration
in IPS mode, when the engine is set to midstream=true.

# Behavior

We expect the engine to define the exception policy for midstream as `ignore`,
as that's the default configuration value when midstream flows are accepted.
This means we should see ``alert`` and ``http`` events.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
