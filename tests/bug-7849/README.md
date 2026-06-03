Unknown ethertype reporting in anomaly events.

When the decoder encounters an ethertype it does not handle, it raises the
``decoder.ethernet.unknown_ethertype`` anomaly event (alongside
``decoder.{vlan,etag,vntag}.unknown_type`` when the unrecognized ethertype
follows a tag). These tests check that the ethernet event includes the
ethertype value that could not be decoded in the ``anomaly.ether_type``
field, using the same format as the ``ether.ether_type`` value, and that
for tagged frames it is the innermost (not the outer tag) ethertype.

Test cases:

  bug-7849-01  Untagged frame: the anomaly event includes ether_type and it
               matches the packet-level ether.ether_type.
  bug-7849-02  VLAN-tagged frame: the ethernet unknown_ethertype event reports
               the inner ethertype, while ether.ether_type is the outer VLAN
               tag ethertype; the vlan.unknown_type event is also raised.
  bug-7849-03  E-Tag (802.1BR) frame: same, with the E-Tag ethertype as the
               outer value.
  bug-7849-04  VN-Tag (802.1Qbh) frame: same, with the VN-Tag ethertype as the
               outer value.

https://redmine.openinfosecfoundation.org/issues/7849
https://redmine.openinfosecfoundation.org/issues/8142
