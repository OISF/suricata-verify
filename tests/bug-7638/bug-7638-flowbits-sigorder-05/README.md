Description
-----------

Test that a ruleset whose flowbit dependencies form a diamond, with no cyclic
dependencies, is accepted by the flowbit dependency resolver without any
error. The only expected warning is for flowbit 'S', which is checked but
never set.

PCAP
----

None

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7638
