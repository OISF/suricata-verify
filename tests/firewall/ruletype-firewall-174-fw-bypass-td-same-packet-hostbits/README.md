Expectation
-----------

Companion to test ruletype-firewall-172-no-fw-bypass-td-same-packet-hostbits.

With a firewall rule using `bypass` in the ruleset, a threat detection
`hostbits` change on a packet that is not bypassed is still visible to a rule
checking the bit on the same packet.

Pcap
----

Reused from test ruletype-firewall-185-bypass-td-post-match-side-effects.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8459
