# Test

Check the expected default behavior,  in versions 6 and 7 of Suricata, for IDS
mode.

# Behavior

In both 6 and 7, the default behavior is to 'ignore' in case of traffic
exceptions, in IDS mode.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
