# detect-bsize-completion-state

Non-firewall pin for the eof semantics of engines registered at a protocol
completion state.

A `bsize` negative only finalizes at engine eof. Such an engine has no P+1,
so the tx end state is its eof: `ntp.reference_id` is registered at progress
1, the NTP completion state, and the negated size must be decided there.

The NTP pcap carries two requests and two replies, each its own tx, so the
rule alerts once per packet.
