Test
====

It seems that Suricata will log an applayer event for a dropped flow, for the
second packet of the flow. This test demonstrates such behavior, so we can
investigate it.

This test demonstrates this behavior with the HTTP protocol.


PCAP
====

PCAP is the result of extracting the http packets from a pcap representing a
curl to the www.testmyids.com site.
