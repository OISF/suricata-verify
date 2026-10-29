Description
-----------

Show that the flowbits SET_READ shortcut in SCSigLessThan
(src/detect-engine-sigorder.c) swallows SCSigOrderByHostbitsCompare for rules that
have no flowbit dependency on each other.

Two signatures that are both flowbits SET_READ and share an action take the
early `return 1` and never reach the remaining comparators. The host bit
dependency between them is therefore never considered, and the reader can be
placed ahead of its setter.

Each pair below is listed setter first and carries the same host bit dependency.
The only difference is the flowbits usage:

    sid:1  hostbits:set,hb;             + flowbits SET_READ
    sid:2  xbits:isset,hb,track ip_src; + flowbits SET_READ
    sid:3  hostbits:set,hb;
    sid:4  xbits:isset,hb,track ip_src;

Expected, and what the control pair gets:

    sid:3 -> sid:4      setter before reader

What the flowbits pair gets instead:

    sid:2 -> sid:1      reader before setter

The flowbits signatures sort ahead of the plain ones because
SCSigOrderByFlowbitsCompare ranks SET_READ above NOT_USED; only the order
within each pair is the subject of this test.

This test pins the current behaviour. When the shortcut stops bypassing the
remaining comparators, lines 1 and 2 become sid:1 then sid:2 and the
expectations here need to be swapped.

PCAP
----

None

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7638
