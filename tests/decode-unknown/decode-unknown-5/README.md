Check that, for an E-Tag (802.1BR) frame carrying an unrecognized inner
ethertype, the ``decoder.ethernet.unknown_ethertype`` event reports the
ethertype that could not be decoded (RARP, ``0x8035``) in
``anomaly.ether_type``, while ``ether.ether_type`` remains the outer E-Tag
ethertype (``0x893F``).

The input pcap is a single E-Tag (ethertype 0x893F) frame whose inner
ethertype is RARP (0x8035), which the decoder does not handle.

https://redmine.openinfosecfoundation.org/issues/7849
