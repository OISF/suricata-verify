Expectation
-----------

An app-layer threat detection rule on a transaction the firewall bypassed must
not change a dataset. A second flow from the same host probes the dataset. The
entry must not be there.

Pcap
----

Reused from test ruletype-firewall-185-bypass-td-post-match-side-effects.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8459
