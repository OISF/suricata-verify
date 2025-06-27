Purpose
-------
Validate that pcap-file.delete-when-done=non-alerts preserves the input PCAP
when an alert is generated via a stream-reassembly rule.

The rule uses stream_size to match TLS server hello data exceeding a threshold,
triggering an alert during stream reassembly. Because an alert is present, the
PCAP file must NOT be deleted.

This test ensures that alerts generated during stream processing are correctly
accounted for by the delete-when-done logic.

Ticket: https://redmine.openinfosecfoundation.org/issues/7786
