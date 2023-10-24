Test
====

Tests a case where the NULL character is sent in HEX coding in the HTTP URL and
normalized path string is checked.

Behavior
========

The null character will lead to no http traffic being recognzied by the stream,
and therefore no rule matching on HTTP traffic will be triggered. We have a
single simple TCP rule to confirm that Suricata indeed sees the stream and is
generating alerts.

Pcap
====

Created using Scapy and based on unit test content.
