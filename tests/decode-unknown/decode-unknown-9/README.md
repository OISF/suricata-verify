Check that, for a Linux cooked capture v2 (SLL2) packet, the
``decoder.ethernet.unknown_ethertype`` event reports the ethertype the
decoder could not handle (RARP, ``0x8035``) in the top-level
``unknown_ether_type`` field of both the anomaly record and the alert.

The SLL2 header holds the protocol in its first field rather than its last,
so the VLAN tag that the protocol announces starts after the whole 20-byte
header. The packet has no ethernet header, so the records have no ``ether``
object.

The input pcap is a single SLL2 packet (link type 276) with protocol 0x8100,
a VLAN tag (VID 5), and the RARP ethertype, which the decoder does not
handle.

https://redmine.openinfosecfoundation.org/issues/7849
https://redmine.openinfosecfoundation.org/issues/8142
