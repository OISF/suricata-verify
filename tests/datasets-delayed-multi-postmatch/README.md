Test
====

Test datasets only sets when there is a full signature match.
Test is with a signature using different keywords matching at different stages,
and pcap having different packets making the transaction progress step by step.
And test is using a multi-buffer to test that we only save the right occurences.

https://redmine.openinfosecfoundation.org/issues/5576

PCAP
====

Pcap crafted with some http server and some python client that delays or not the writing of the headers
