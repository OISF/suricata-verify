Check that anomaly events for unknown ethertypes include the ethertype
the decoder could not handle in the top-level ``unknown_ether_type`` field, and
that it matches the ``ether.ether_type`` value for an untagged frame. The
alert from a ``decode-event:ethernet.unknown_ethertype`` rule carries the
same field.

https://redmine.openinfosecfoundation.org/issues/7849
