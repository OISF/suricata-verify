Check that, for an ethernet frame carried in a GRE tunnel, the
``decoder.ethernet.unknown_ethertype`` event raised for the tunneled packet
reports the ethertype the decoder could not handle (RARP, ``0x8035``) in
``unknown_ether_type``. That ethertype follows a VLAN tag in the inner
frame, and the event's ``ether`` object describes the inner frame, so
``ether.ether_type`` is the VLAN tag ethertype (``0x8100``). The
``decoder.vlan.unknown_type`` event raised for the same packet carries the
same ``unknown_ether_type``.

The alert for the tunneled packet's event carries the RARP value in the
top-level ``unknown_ether_type`` field. An alert on the outer GRE packet,
which has no such event, does not have the field.

The input pcap is a single IPv4 packet carrying GRE (protocol 0x6558,
transparent ethernet bridging). The inner ethernet frame has its own MAC
addresses, a VLAN tag (VID 9), and the RARP ethertype, which the decoder
does not handle.

https://redmine.openinfosecfoundation.org/issues/7849
https://redmine.openinfosecfoundation.org/issues/8142
