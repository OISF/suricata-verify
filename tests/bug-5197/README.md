Description
===========
This test is to demonstrate Redmine bug 5197.
`fast_pattern` assignment of specific content results in false negatives.
For the PCAP used in this test, sid:1 and sid:2 are the exact same rules except for an explicit
`fast_pattern` keyword in sid:2. But, only sid:1 fires.
Another issue that can be seen is that changing the position of `fast_pattern` can also result
in some false negatives. sid:3 and sid:6 are such examples. Only sid:6 fires in this case.

PCAP
====
PCAP comes from the Redmine ticket https://redmine.openinfosecfoundation.org/issues/5197
