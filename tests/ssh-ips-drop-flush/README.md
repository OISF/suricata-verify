# Description

An SSH flow that is dropped in IPS mode before either side sends
NewKeys must still produce an `ssh` event.

The SSH eve logger's condition is failure-only: a successful record is
emitted by the flow-end flush, where the engine logs unconditionally.
That flush never happens for a dropped flow - flow timeout/shutdown skip
`FLOW_ACTION_DROP` flows - so the record used to be lost entirely.

The fix schedules the tx loggers once when the flow action becomes drop:
the dropping packet's output stage runs them, and the SSH log condition
admits a dropped flow. The app-layer disable path raises the same flush
as a fallback for drops that do not go through the transition. This test
pins that: the `ssh` event is emitted at the packet that drops the flow,
with both banners, while the flow is dropped.

# Rules

Rule 1 (`sid:1`) only sets a flowbit when the server banner is parsed,
without alerting. Rule 2 (`sid:2`) drops the flow on the first
server-to-client ACK after that banner - a packet that carries no
app-layer data. The drop therefore exercises the drop-transition flush,
not just the log condition.

# PCAP

`input.pcap` is the SSH banner-only fixture from `tests/ssh-banner-only`
(client banner, then server banner, no key exchange). The drop fires at
pcap_cnt 14 and the `ssh` event is emitted at pcap_cnt 14.
