Decoding of unknown (unhandled) ethertypes.

When the decoder encounters an ethertype it does not handle, it increments
the ``decoder.unknown_ethertype`` counter and, from 8.0, raises the
``decoder.ethernet.unknown_ethertype`` anomaly event (alongside
``decoder.{vlan,etag,vntag}.unknown_type`` when the unrecognized ethertype
follows a tag). From 9.0 the ethernet event also reports the offending
value in the ``anomaly.ether_type`` field, using the same format as
``ether.ether_type``; for tagged frames this is the innermost (not the
outer tag) ethertype.

Test cases:

  decode-unknown-1  Pre-8.0 behavior: only the decoder.unknown_ethertype
                    stats counter is incremented (no anomaly event).
  decode-unknown-2  8.0+ behavior: the decoder.ethernet.unknown_ethertype
                    anomaly event is raised with ether.ether_type.
  decode-unknown-3  9.0+ untagged frame: the anomaly event includes
                    ether_type and it matches the packet-level
                    ether.ether_type.
  decode-unknown-4  9.0+ VLAN-tagged frame: the ethernet unknown_ethertype
                    event reports the inner ethertype, while ether.ether_type
                    is the outer VLAN tag ethertype; the vlan.unknown_type
                    event is also raised.
  decode-unknown-5  9.0+ E-Tag (802.1BR) frame: same, with the E-Tag
                    ethertype as the outer value.
  decode-unknown-6  9.0+ VN-Tag (802.1Qbh) frame: same, with the VN-Tag
                    ethertype as the outer value.

https://redmine.openinfosecfoundation.org/issues/7849
https://redmine.openinfosecfoundation.org/issues/8142
