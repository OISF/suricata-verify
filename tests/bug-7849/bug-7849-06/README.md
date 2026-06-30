Check that, for a VN-Tag (802.1Qbh) frame carrying an unrecognized inner
ethertype, the ``decoder.vntag.unknown_type`` anomaly event reports the
ethertype that could not be decoded (RARP, ``0x8035``).

The input pcap is a single VN-Tag (ethertype 0x8926) frame whose inner
ethertype is RARP (0x8035), which the decoder does not handle.

https://redmine.openinfosecfoundation.org/issues/7849
