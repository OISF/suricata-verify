# quic-concurrent-version-negotiation

A v2 client Initial followed by Version Negotiation advertising v1 must retain the version-zero transaction for EVE logging and rules.

All packets use the same UDP five-tuple. These deterministic synthetic captures contain valid encrypted Initial packets and exercise passive Hello extraction, not a complete TLS session.

Regenerate with `python3 util/gen-quic-connections.py` (requires cryptography).

Ticket: https://redmine.openinfosecfoundation.org/issues/9228
