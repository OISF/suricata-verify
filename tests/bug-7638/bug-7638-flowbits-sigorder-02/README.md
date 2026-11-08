Description
-----------

Test to show the order of flowbits after dependency resolution among the
signatures with cyclic dependencies.

1 -> 2
^    |
|    |
 ----

The signatures can never match at runtime. A warning is logged for each
signature in the cycle saying it will never match, and one saying the flowbit
dependencies could not be resolved. The ruleset is still loaded.

PCAP
----

None

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7638
