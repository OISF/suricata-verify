Description
-----------

Boundary case: an isset with exactly 100 OR'd alternatives, the maximum
MAX_TOKENS permits in src/detect-flowbits.c, with every alternative set by a
rule of its own.

    sid:1        flowbits:isset,<100 names>;  flowbits:set,done;
    sid:2..101   flowbits:set,<one of the 100 names>;
    sid:102      flowbits:isset,done;

The ruleset is accepted, and sid:1 ends up with 100 incoming edges in the
dependency graph, so all 100 setters are forced ahead of it. At runtime a
single satisfied alternative is enough, so 99 of those 100 ordering
constraints are not required by any flow.

Two separate limits meet here. MAX_TOKENS caps the alternatives at 100, but
DetectFlowbitParse first copies the entire name list into a 256 byte buffer,
so 100 alternatives are only reachable with very short names. The names in
this test are one or two characters for that reason; with longer names the
parse fails with "pcre2_substring_copy_bynumber failed" long before the token
limit is hit.

101 alternatives are rejected with "Number of flowbits exceeds maximum
allowed: 100".

PCAP
----

None

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7638
