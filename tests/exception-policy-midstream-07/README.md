# Test

Check that the midstream-policy is properly applied in case it's set to
``bypass`` in IPS mode when the engine firstly sees the stream during ACK
state.

# Behavior

We expect to only see a ``flow`` event logged, as the flow will be bypassed.

# Pcap

Pcap is borrowed from the smb3-01 SV test.
