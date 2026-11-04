Check that, for a GRE tunnel with protocol 0x8100, the
``decoder.ethernet.unknown_ethertype`` event raised for the tunneled packet
reports the ethertype the decoder could not handle (RARP, ``0x8035``) in
``unknown_ether_type``, and that the alert for that packet carries the same
field. The tunneled packet starts at a VLAN header and has no ethernet header.
An alert on the outer GRE packet, which has no such event, does not have the
field.

The input pcap is a single IPv4 packet carrying GRE (protocol 0x8100). The
tunneled data is two VLAN tags (VID 10, then VID 20) followed by the RARP
ethertype, which the decoder does not handle.

https://redmine.openinfosecfoundation.org/issues/7849
https://redmine.openinfosecfoundation.org/issues/8142
