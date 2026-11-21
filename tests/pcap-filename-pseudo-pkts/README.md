Verify that pcap_filename is present in EVE JSON output for
pseudo-packets (e.g. fileinfo events from truncated files).

This reuses the pcap from bug-5392 which triggers a file truncation event.
The generated stream pseudo-packet carries pcap_v.pfv propagated from the
flow (set in StreamTcpDetectLogFlush), so this exercises the per-packet
pfv->filename path in OutputJsonBuilderBuffer.

Related to https://redmine.openinfosecfoundation.org/issues/5255
