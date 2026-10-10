Decoding of unknown (unhandled) ethertypes.

When the decoder encounters an ethertype it does not handle, it increments
the ``decoder.unknown_ethertype`` counter and, from 8.0, raises the
``decoder.ethernet.unknown_ethertype`` anomaly event (alongside
``decoder.{vlan,etag,vntag}.unknown_type`` when the unrecognized ethertype
follows a tag). From 9.0 every anomaly record and alert for the packet
reports that ethertype in a top-level ``unknown_ether_type`` field,
using the same format as ``ether.ether_type``. Decoding stops at that
ethertype, so a packet has at most one; for tagged frames it is the
ethertype after the tag, while
``ether.ether_type`` holds the ethernet header's type (the tag ethertype).

Test cases:

  decode-unknown-1  Pre-8.0 behavior: only the decoder.unknown_ethertype
                    stats counter is incremented (no anomaly event).
  decode-unknown-2  8.0+ behavior: the decoder.ethernet.unknown_ethertype
                    anomaly event is raised with ether.ether_type.
  decode-unknown-3  9.0+ untagged frame: the anomaly event includes
                    unknown_ether_type and it matches
                    ether.ether_type; the alert has unknown_ether_type.
  decode-unknown-4  9.0+ VLAN-tagged frame: the ethernet unknown_ethertype
                    event reports the ethertype after the tag, while
                    ether.ether_type is the VLAN tag ethertype; the
                    vlan.unknown_type event is also raised, with the same
                    unknown_ether_type; the alert has unknown_ether_type.
  decode-unknown-5  9.0+ E-Tag (802.1BR) frame: same, with the E-Tag
                    ethertype in ether.ether_type.
  decode-unknown-6  9.0+ VN-Tag (802.1Qbh) frame: same, with the VN-Tag
                    ethertype in ether.ether_type.
  decode-unknown-7  9.0+ GRE tunnel carrying a VLAN-tagged ethernet
                    frame: the event raised for the tunneled packet
                    reports the ethertype after the inner frame's VLAN
                    tag; the alert for the tunneled packet has
                    unknown_ether_type and the alert for the outer packet
                    does not.
  decode-unknown-8  9.0+ GRE tunnel with protocol 0x8100: the tunneled
                    packet starts at a VLAN header, with no ethernet
                    header; its event and alert report the ethertype
                    after the second VLAN tag, and the alert for the
                    outer packet has no unknown_ether_type.

https://redmine.openinfosecfoundation.org/issues/7849
https://redmine.openinfosecfoundation.org/issues/8142
