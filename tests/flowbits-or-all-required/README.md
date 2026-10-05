Description
-----------

Counterpart to flowbits-or-inconsequential: when every alternative of an OR'd
flowbit check is set by a rule that does not depend on the reader, each edge
the graph draws is a real constraint and the current treatment is correct.

Ruleset:

    sid:1  flowbits:set,A;
    sid:2  flowbits:set,B;
    sid:3  flowbits:isset,A|B;  flowbits:set,D;
    sid:4  flowbits:isset,D;

sid:3 collects an edge from sid:1 (for A) and from sid:2 (for B), and sends one
on to sid:4 (for D). No cycle, and the order comes out as:

    sid:1, sid:2, sid:3, sid:4

This test exists to bound the problem. Treating every alternative as mandatory
is only wrong when an alternative is inconsequential; it is harmless here, so a
fix must keep this ordering intact.

PCAP
----

None

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7638
