Expectation
-----------

IP-only variant of test ruletype-firewall-185-bypass-td-post-match-side-effects.

An IP-only threat detection rule must leave no state behind on a packet the
firewall bypassed. A second flow from the same host probes the bit. It must
not be set.

Pcap
----

Reused from test ruletype-firewall-185-bypass-td-post-match-side-effects.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8459
