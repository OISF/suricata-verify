# Test

Check the expected auto behavior for exception policies,  in versions 6 and 7 of
Suricata, in IPS mode.

# Behavior

In 7, the auto behavior is 'drop-packet' and/or 'drop-flow' in case of traffic
exceptions, in IPS mode. In 6, the auto behavior is to 'ignore'.

# Pcap

Pcap is the result of a curl to www.testmyids.com, later extracted with
Wireshark to keep the ``http`` packets only.
