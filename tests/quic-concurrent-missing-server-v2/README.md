# quic-concurrent-missing-server-v2

Server Initial packets are missing from the capture. Client tails use unseen server SCIDs as DCIDs, but retain the original Initial keys. Shared or empty client SCIDs must be disambiguated by decryption.

All packets use the same UDP five-tuple. These deterministic synthetic captures contain valid encrypted Initial packets and exercise passive Hello extraction, not a complete TLS session.

Regenerate with `python3 util/gen-quic-connections.py` (requires cryptography).

Ticket: https://redmine.openinfosecfoundation.org/issues/9228
