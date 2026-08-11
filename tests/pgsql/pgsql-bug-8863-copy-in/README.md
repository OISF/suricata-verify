Purpose
-------

Companion to `pgsql-bug-8863-copy-out`, which covers the three parser desync cases. This
test covers what happens *after* a malformed CopyInResponse: the backend's turn
is over either way, so the frontend still enters CopyIn mode and its CopyData
messages must still be accounted for.

Pcap
----

Crafted by Claude, using scapy and the ticket description for reproducing
traffic. See `writepcap.py`.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8863
