# Redmine #8823 tcp-data fopen failure

Regression test for https://redmine.openinfosecfoundation.org/issues/8823.

The pcap is the ticket's minimal TCP handshake, one-byte data segment, and
acknowledgement. The test enables the `tcp-data` directory output and places a
regular file at the path where its `tcp/` directory should be. This makes the
per-chunk `fopen` fail with `ENOTDIR`. Before the fix, `BUG_ON(fp == NULL)`
terminated Suricata; a fixed build logs the failure and keeps processing.

Regenerate the pcap with `./make-pcap.py`.
