# Description

With XDP bypass and `pinned-maps: true` flows stay bypassed across a restart of
Suricata: the XDP filter and its flow tables stay in place when Suricata exits,
and at start Suricata takes over the flows it finds in the pinned maps.

Suricata is run twice on the same interface with the same pcap. The first run
(first-run.sh, started as setup script) bypasses the 2 flows of the pcap and
stops. The second run is the one of the test runner:

- after the first stop the pinned IPv4 flow table holds the entries of both
  flows (expected-keys.txt, one line per direction of a flow, as dumped on a
  little-endian host),
- in the second run no packet reaches Suricata, as shown by the rule that
  alerts on, and bypasses, every flow of the pcap,
- the second run counts the 101 packets of the pcap as bypassed and ends the 2
  flows from the pinned map as capture-bypassed flows,
- after the second stop the entries are still in the pinned map.

The XDP filter and the pinned maps are then removed from the test interface.

# Ticket

https://redmine.openinfosecfoundation.org/issues/9455

# PCAP

The pcap of bypass-stats-shutdown: one TCP flow of 100 packets and one UDP flow
of a single packet.
