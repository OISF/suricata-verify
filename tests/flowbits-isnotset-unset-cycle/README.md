Description
-----------

Two signatures that each unset the flowbit the other checks with isnotset form
a cycle in the flowbit dependency graph, made only of unset -> isnotset edges.

isnotset already matches before the bit was ever set, so both signatures can
match on the first packet of a flow. Such a cycle is not an unsatisfiable
dependency and must not be reported as an error.

PCAP
----

None

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7771
