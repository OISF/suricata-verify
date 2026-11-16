Expectation
-----------

Companion to test ruletype-firewall-170-bypass-iponly-td-post-match-side-effects.

Without a bypass, an IP-only threat detection rule's `xbits:toggle` must run
once, leaving the bit set for the probe on the second flow.

Pcap
----

Reused from test ruletype-firewall-185-bypass-td-post-match-side-effects.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8459
