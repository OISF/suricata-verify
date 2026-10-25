# quic-concurrent-bypass

Explicit bypass must wait while another known connection is unfinished.

All packets use the same UDP five-tuple. These deterministic synthetic captures contain valid encrypted Initial packets and exercise passive Hello extraction, not a complete TLS session.

Regenerate with `python3 util/gen-quic-connections.py` (requires cryptography).

Ticket: https://redmine.openinfosecfoundation.org/issues/9228
