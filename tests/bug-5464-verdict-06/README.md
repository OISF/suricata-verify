# Test and Showcase the Verdict Field in IDS mode

Showcase verdict field output with reject in IDS mode, for ICMP.

# Behavior

We should see an alert with ``verdict.action: alert`` and ``verdict.reject:
[icmp-prohib]``.

# Pcap

Comes from the test `decode-teredo-01` as it has a good variety of protocols.
