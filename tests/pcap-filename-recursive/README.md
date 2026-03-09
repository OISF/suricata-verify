Verify that pcap_filename in EVE JSON output reflects the file each
connection's packets came from, not the last file the RX thread processed.

Two pcap files are fed with --pcap-file-recursive.  alert.pcap is processed
first; http.pcap is processed last, so the global pcap_filename points to
http.pcap at shutdown.  The flow event for the alert.pcap connection must
report alert.pcap (read from the per-flow pfv), demonstrating that the race
between the RX thread advancing to the next file and workers/flow-manager
logging events is resolved correctly.

The pcap files are copies of existing test captures:
  alert.pcap  - copy of tests/bug-7414-decoder-event-01/ip_secopt.pcap
  http.pcap   - copy of tests/bug-5392/TPWhite-carved-out-7787-s1.pcap
Local copies are required because --pcap-file-recursive reads an entire
directory; relative paths to other test directories cannot be used.

Related to https://redmine.openinfosecfoundation.org/issues/5255
