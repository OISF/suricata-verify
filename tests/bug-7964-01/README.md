Test that the engine correctly issues a wrong ip version event and flags packet
as invalid when decoding an IPv4-in-IPv6 packet with wrong/ invalid IP version.

PCAP
----

Created by using bug-4571-06 pcap and replacing IPv4 version with invalid value.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7964
