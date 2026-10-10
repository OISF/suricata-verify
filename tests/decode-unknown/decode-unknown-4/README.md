Check that, for a VLAN-tagged frame whose VLAN tag is followed by an
ethertype the decoder does not handle, the
``decoder.ethernet.unknown_ethertype`` event reports that ethertype
(RARP, ``0x8035``) in ``unknown_ether_type``, while ``ether.ether_type``
holds the ethernet header's type, the VLAN tag ethertype (``0x8100``). The
``decoder.vlan.unknown_type`` event raised for the same frame carries the
same ``unknown_ether_type``.

The alert from a ``decode-event:ethernet.unknown_ethertype`` rule carries
the RARP value in the top-level ``unknown_ether_type`` field, and its
``ether.ether_type`` is the VLAN tag ethertype.

The input pcap is a single VLAN-tagged (0x8100, VID 100) frame whose
VLAN tag is followed by RARP (0x8035), which the decoder does not
handle.

https://redmine.openinfosecfoundation.org/issues/7849
https://redmine.openinfosecfoundation.org/issues/8142
