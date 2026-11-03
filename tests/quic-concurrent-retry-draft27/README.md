# quic-concurrent-retry-draft27

A draft-27 Retry must pass its version-specific integrity check and reset the existing context, even when only one context is allowed.

All packets use the same UDP five-tuple. These deterministic synthetic captures contain valid encrypted Initial packets and exercise passive Hello extraction, not a complete TLS session.

Regenerate with `python3 util/gen-quic-connections.py` (requires cryptography).

Ticket: https://redmine.openinfosecfoundation.org/issues/9228
