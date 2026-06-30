Check that, for VLAN-tagged frames carrying an unrecognized inner
ethertype, the anomaly event reports the innermost ethertype that could
not be decoded (RARP, ``0x8035``) rather than the outer VLAN tag ethertype
(``0x8100``).

The input pcap is a single VLAN-tagged (0x8100, VID 100) frame whose inner
ethertype is RARP (0x8035), which the decoder does not handle.

https://redmine.openinfosecfoundation.org/issues/7849
https://redmine.openinfosecfoundation.org/issues/8142
