Description
-----------

Test to show the order of flowbits after dependency resolution among the
signatures with cyclic dependencies.

1 -> 2
^    |
|    |
 ----

Signatures must be rejected from loading as they can never meet at runtime.

PCAP
----

None

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7638
