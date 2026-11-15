Description
-----------

An alternative of an OR'd flowbit check that no flow actually needs still
becomes a mandatory dependency edge, and the edge closes a cycle that cannot
happen at runtime.

DetectFlowbitsAnalyzeSignature records a signature as an isset reader of every
name in an "A|B" list, so CreateGraphFromFlowbitAnalyzer draws an edge from
every setter of every alternative. DetectFlowbitMatchIsset only needs one of
them to be set.

Ruleset:

    sid:1  flowbits:isset,A|B;  flowbits:set,C;
    sid:2  flowbits:isset,C;    flowbits:set,A;
    sid:3  flowbits:set,B;

A valid runtime order exists: sid:3 sets B, sid:1 matches on B and sets C,
sid:2 matches on C and sets A. A is never needed for sid:1 to match.

The graph draws both of these:

    sid:2 -> sid:1    because sid:2 sets A and sid:1 "reads" A
    sid:1 -> sid:2    because sid:1 sets C and sid:2 reads C

Both are set edges, so they carry equal weight and cycle resolution has no
lower priority edge to drop. The ruleset is rejected with a cyclic dependency
error even though sid:3 makes the A edge irrelevant.

PCAP
----

None

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7638
