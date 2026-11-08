# quic-concurrent-v2

Three independent handshakes are interleaved, including a duplicate tail fragment arriving before the middle. Each SNI and rule must appear once.

All packets use the same UDP five-tuple. These deterministic synthetic captures contain valid encrypted Initial packets and exercise passive Hello extraction, not a complete TLS session.

Regenerate with `python3 util/gen-quic-connections.py` (requires cryptography).

Ticket: https://redmine.openinfosecfoundation.org/issues/9228
