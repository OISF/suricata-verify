# Description

Regression test for issue 8629: SMB transactions must not be allowed to grow
without bound on asynchronous (one-sided) flows.

When Suricata only ever sees one direction of a flow, SMB requests wait forever
for responses that never arrive. Once the transaction list passes `smb.max-tx`
the parser stops trying to handle this gracefully and instead raises the
`too_many_transactions` event and returns an error, which puts the flow's
app-layer parser into an error state and stops further SMB processing.

The test lowers `smb.max-tx` so the small capture reaches the limit, and checks
that SMB is parsed up to that point, that the event is raised, and that the flow
is put into an error state (`app_layer.error.smb.parser`).

# PCAP

A single SMB2/DCERPC session derived from the `dcerpc-smb-test-01` capture,
reduced to the client->server direction only so it is a genuine one-sided
capture. It begins with a SYN followed by an ACK from the same host, which is
how the engine detects an asynchronous stream, so `stream.async-oneside` is
enabled.
