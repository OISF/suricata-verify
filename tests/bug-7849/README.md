Unknown ethertype reporting in anomaly events.

When the decoder encounters an ethertype it does not handle, it raises an
unknown-ethertype anomaly event (``decoder.ethernet.unknown_ethertype``, or
one of the ``decoder.{vlan,etag,vntag}.unknown_type`` events for tagged
frames). These tests check that the event includes the ethertype value that
could not be decoded in the ``anomaly.ether_type`` field, and that the
eve-log ``ethertype-hex`` option controls how the packet-level
``ether.ether_type`` value is displayed.

The anomaly ``ether_type`` is always a hexadecimal string, e.g., ``0xfbb7``.
The packet-level ``ether.ether_type`` defaults to a decimal value and is
displayed as a hexadecimal string only when ``ethertype-hex`` is enabled.

Test cases:

  bug-7849-01  Default config: the anomaly event includes ether_type and the
               packet-level ether.ether_type is displayed in decimal.
  bug-7849-02  ethertype-hex enabled: ether.ether_type is displayed in hex.
  bug-7849-03  ethertype-hex disabled: ether.ether_type is displayed in
               decimal (matching the default).
  bug-7849-04  VLAN-tagged frame with an unrecognized inner ethertype: both
               the ethernet and decoder.vlan.unknown_type events report the
               innermost ethertype that could not be decoded rather than the
               outer VLAN tag ethertype.
  bug-7849-05  E-Tag (802.1BR) frame: decoder.etag.unknown_type reports the
               unrecognized inner ethertype.
  bug-7849-06  VN-Tag (802.1Qbh) frame: decoder.vntag.unknown_type reports the
               unrecognized inner ethertype.

https://redmine.openinfosecfoundation.org/issues/7849
https://redmine.openinfosecfoundation.org/issues/8142
