Description
-----------

Test that a ruleset whose flowbits form a plain dependency chain, with no
cyclic dependencies, is accepted by the flowbit dependency resolver without
any error. The only expected warning is for flowbit 'E', which is checked but
never set.

PCAP
----

None

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7638
