# Test

Check the expected default behavior for Exception Policies in IPS, in Suricata
versions 6 and 7.

# Behavior

In 7, the auto behavior is to drop-packet and/or drop-flow in case of traffic
exceptions, in IPS mode. In 6, the default behavior is to 'ignore'.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
