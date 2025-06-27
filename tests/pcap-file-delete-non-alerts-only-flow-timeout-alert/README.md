Purpose
-------
Validate that pcap-file.delete-when-done=non-alerts preserves the input PCAP
when an alert is generated via a flow-timeout (stream_size) rule.

The rule uses stream_size to match only after the TLS server hello data exceeds
a threshold. This triggers an alert during flow timeout processing rather than
inline packet inspection. Because an alert is present, the PCAP file must NOT
be deleted.

This test ensures that alerts generated during flow cleanup are correctly
accounted for by the delete-when-done logic.

Ticket: https://redmine.openinfosecfoundation.org/issues/7786
