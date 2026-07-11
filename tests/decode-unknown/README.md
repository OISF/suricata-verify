Decoding of unknown (unhandled) ethertypes.

When the decoder encounters an ethertype it does not handle, it increments
the ``decoder.unknown_ethertype`` counter and, from 8.0, raises the
``decoder.ethernet.unknown_ethertype`` anomaly event.

Test cases:

  decode-unknown-1  Pre-8.0 behavior: only the decoder.unknown_ethertype
                    stats counter is incremented (no anomaly event).
  decode-unknown-2  8.0+ behavior: the decoder.ethernet.unknown_ethertype
                    anomaly event is raised with ether.ether_type.
