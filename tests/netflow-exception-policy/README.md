## Test

Check that an applied exception policy is logged on the `netflow` event
in the same form it already appears on the `flow` event. The midstream
packet in the pcap trips `stream.midstream-policy` set to `bypass`,
which records the `stream_midstream` exception policy on the flow.

Both the `flow` event and the `netflow` event for this connection are
expected to carry an `exception_policy` entry with target
`stream_midstream` and policy `bypass`.

Bug: https://redmine.openinfosecfoundation.org/issues/8499

## Pcap

Synthetic pcap containing a single midstream TCP packet. There is no
preceding SYN for Suricata to track from the start, so the stream is
seen midstream and the bypass exception policy is applied. The pcap
can be regenerated from `pcap_gen.py`.
