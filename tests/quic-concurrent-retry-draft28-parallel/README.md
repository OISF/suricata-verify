# quic-concurrent-retry-draft28-parallel

A draft-28 Retry is associated by its original DCID integrity tag when connections share a client SCID. Invalid tags, wrong original DCIDs, and repeated Retry packets must preserve unfinished CRYPTO buffers.

All packets use the same UDP five-tuple. These deterministic synthetic captures contain valid encrypted Initial packets and exercise passive Hello extraction, not a complete TLS session.

Regenerate with `python3 util/gen-quic-connections.py` (requires cryptography).

Ticket: https://redmine.openinfosecfoundation.org/issues/9228
