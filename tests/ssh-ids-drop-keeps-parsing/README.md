# Description

A stateful `drop` rule in IDS mode sets the flow action but parsing
continues (`StreamTcpCheckFlowDrops()` only ends the app layer in IPS
mode). The one-shot SSH record must therefore not be emitted at the
alert, where the server banner would be missing, and the drop must not
consume it with a success record: the condition stays failure-first and
the record is emitted by the flow-end flush, carrying both banners.

# Rules

`sid:1` drops the flow on the client banner. The pcap then carries the
server banner; the `ssh` event must contain both banners.

# PCAP

`input.pcap` is crafted by `craft-pcap.py` (see that file): the client
banner is parsed and released for inspection before the server banner
arrives, so a premature record would only carry the client banner.
