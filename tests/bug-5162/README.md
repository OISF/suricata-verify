Description
===========
This test demonstrates bug 5162.
Inspection of SMB traffic without SMB/DCERPC does not work correctly.
In the test, sid:1 and sid:2 are identical except sid:2 has an extra byte in first `content`
match. But, only sid:2 alerts when sid:1 should as well.
This works with a standalone `within` as in sid:5.
Logically, sid:3 and sid:4 are the same but only sid:4 alerts.
As demonstrated by sid:6 and sid:7, this issue may be related to redmine ticket 5197.

PCAP
====
PCAP comes from Redmine bug https://redmine.openinfosecfoundation.org/issues/5162
