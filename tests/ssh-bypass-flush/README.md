# Description

An SSH flow that gets bypassed after both banners but before either side
sends NewKeys must still produce an `ssh` event.

The SSH eve logger's condition is failure-only: a successful record is
emitted by the flow-end flush. A bypassed flow frees the app-layer state
in the flow worker and gets no flow-end pseudo packets, so the record was
lost. The bypass transition now schedules the pending tx loggers once
(like a drop does), and the SSH log condition admits a bypassed flow.

# Rules

Rule 1 (`sid:1`) only sets a flowbit when the server banner is parsed.
Rule 2 (`sid:2`) bypasses the flow on the first server-to-client ACK after
that banner - a packet that carries no app-layer data. The bypass
therefore exercises the bypass-transition flush, not just the log
condition.

# PCAP

`input.pcap` is the SSH banner-only fixture from `tests/ssh-banner-only`
(client banner, then server banner, no key exchange). The bypass fires at
pcap_cnt 14 and the `ssh` event is emitted at pcap_cnt 14.
