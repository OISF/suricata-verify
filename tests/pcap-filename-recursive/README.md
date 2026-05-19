Verify that pcap_filename in EVE JSON output reflects the file each
connection's packets came from, not the last file the RX thread processed.

Two pcap files are fed with --pcap-file-recursive.  Regardless of processing
order, each event must report the pcap it actually belongs to (via the
per-flow/per-packet pfv), not the stale global.

The pcap files are copies of existing test captures:
  alert.pcap  - copy of tests/bug-7414-decoder-event-01/ip_secopt.pcap
  http.pcap   - copy of tests/bug-5392/TPWhite-carved-out-7787-s1.pcap
Local copies are required because --pcap-file-recursive reads an entire
directory; relative paths to other test directories cannot be used.

Related to https://redmine.openinfosecfoundation.org/issues/5255
