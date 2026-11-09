# issue-9085

Redmine ticket: https://redmine.openinfosecfoundation.org/issues/9085

Regression test for unbounded TFTP transaction retention on unidirectional
transactions.

`input.pcap` contains one TFTP read request followed by an ACK in the reverse
direction. `mktftp-request-reply.py` can regenerate it.

The alert rule deliberately uses `udp`, rather than the TFTP application
protocol. With `detect.guess-applayer-tx` enabled, Suricata attaches an
application-layer transaction to such an alert only when an eligible live
transaction exists.

Before the fix, the request transaction remains live while the reply is
processed because its TOCLIENT inspection can never complete. Suricata
therefore attaches the stale request transaction to the reply alert, adding
`tx_id: 0` and the request's `tftp` object.

After TFTP creates the request with
`AppLayerTxData::for_direction(Direction::ToServer)`, cleanup releases the
transaction before the reply. The reply alert is still emitted, but it has no
transaction ID or TFTP request metadata. The test asserts this entirely from
EVE output and requires neither DEBUG nor UNITTESTS.
