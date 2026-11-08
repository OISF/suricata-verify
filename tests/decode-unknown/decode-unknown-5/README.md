Check that, for an E-Tag (802.1BR) frame whose E-Tag header is followed by an
ethertype the decoder does not handle, the
``decoder.ethernet.unknown_ethertype`` event reports that ethertype
(RARP, ``0x8035``) in ``unknown_ether_type``, while ``ether.ether_type``
holds the ethernet header's type, the E-Tag ethertype (``0x893F``). The
``decoder.etag.unknown_type`` event raised for the same frame carries the
same ``unknown_ether_type``.

The input pcap is a single E-Tag (ethertype 0x893F) frame whose
E-Tag header is followed by RARP (0x8035), which the decoder does not
handle.

https://redmine.openinfosecfoundation.org/issues/7849
