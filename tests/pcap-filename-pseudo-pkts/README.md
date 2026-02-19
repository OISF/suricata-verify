Verify that pcap_filename is present in EVE JSON output for
pseudo-packets (e.g. fileinfo events from truncated files).

This reuses the pcap from bug-5392 which triggers a file truncation event.
The generated pseudo-packet lacks a pcap_v.pfv reference, so this tests the
fallback to the global PcapFileGetFilename().

Related to https://redmine.openinfosecfoundation.org/issues/5255
