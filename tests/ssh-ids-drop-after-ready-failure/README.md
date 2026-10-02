# Description

Both banners parse, then a stateful `drop` rule matches the server banner:
the flow action is set after the readiness the old success condition used.
In IDS mode the drop does not stop parsing (`StreamTcpCheckFlowDrops()` only
ends the app layer in IPS mode), so the one-shot SSH tx log must stay
failure-first: the malformed record that follows must still be logged, and
the success record must not be emitted at the drop.

# Rules

`sid:1` drops the flow on the server banner. The pcap then carries a record
header with `pkt_len` 0, which fails the parser unrecoverably
(`invalid_record`).

# PCAP

`input.pcap` is crafted by `craft-pcap.py` (see that file): both banners are
parsed before the drop rule fires, then the invalid record follows.
