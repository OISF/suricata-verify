Expectation
-----------

Without a firewall rule using `bypass`, threat detection `hostbits` changes are
applied at match time, so a rule checking the bit sees it on the same packet.

Pcap
----

Reused from test ruletype-firewall-185-bypass-td-post-match-side-effects.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8459
