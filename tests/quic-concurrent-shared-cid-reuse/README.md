# quic-concurrent-shared-cid-reuse

A completed client Hello sharing a SCID must not suppress a new connection or produce duplicate SNI events on retransmission.

All packets use the same UDP five-tuple. These deterministic synthetic captures contain valid encrypted Initial packets and exercise passive Hello extraction, not a complete TLS session.

Regenerate with `python3 util/gen-quic-connections.py` (requires cryptography).

Ticket: https://redmine.openinfosecfoundation.org/issues/9228
