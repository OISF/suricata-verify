# Test

Check the expected overriding behavior, in IPS mode, if an Exception Policy is
set, regardless of what is defined in the master switch.

# Behavior

We expect to see a flow event with the action set to pass, and the http
protocol event, since a pass policy will still mean inspection, just no detection.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
