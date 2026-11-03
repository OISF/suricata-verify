# quic-concurrent-server-cid

After a server Initial, client Initial packets use its SCID as DCID while retaining the original Initial keys. Capture ordering puts the server response ahead of the final observed client fragment.

All packets use the same UDP five-tuple. These deterministic synthetic captures contain valid encrypted Initial packets and exercise passive Hello extraction, not a complete TLS session.

Regenerate with `python3 util/gen-quic-connections.py` (requires cryptography).

Ticket: https://redmine.openinfosecfoundation.org/issues/9228
