Expectation
-----------

Companion to test ruletype-firewall-185-bypass-td-post-match-side-effects.

A threat detection `xbits:unset` on a packet the firewall bypasses must be
undone: the bit set earlier in the flow is still set for the probe on the second
flow.

Pcap
----

Reused from test ruletype-firewall-185-bypass-td-post-match-side-effects.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8459
