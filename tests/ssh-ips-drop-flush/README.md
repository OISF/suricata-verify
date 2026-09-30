# Description

An SSH flow that is dropped in IPS mode before either side sends
NewKeys must still produce an `ssh` event.

The SSH eve logger's condition is failure-only: a successful record is
emitted by the flow-end flush, where the engine logs unconditionally.
That flush never happens for a dropped flow - the drop disables the app
layer (so no further app-layer update reaches the tx loggers) and flow
timeout/shutdown skip `FLOW_ACTION_DROP` flows - so the record used to
be lost entirely.

The fix runs the tx loggers once from the app-layer disable path, and
the SSH log condition admits a dropped flow. This test pins that: the
`ssh` event is emitted at the packet that disables the app layer, with
both banners, while the flow is dropped.

# Rules

Rule 1 (`sid:1`) only sets a flowbit when the server banner is parsed,
without alerting. Rule 2 (`sid:2`) drops the flow on the first
server-to-client ACK after that banner - a packet that carries no
app-layer data - so the drop is already in place when the *next* packet
disables the app layer. The drop therefore exercises the disable-path
flush, not just the log condition.

# PCAP

`input.pcap` is the SSH banner-only fixture from `tests/ssh-banner-only`
(client banner, then server banner, no key exchange). The drop fires at
pcap_cnt 14 and the `ssh` event is emitted at pcap_cnt 15.
