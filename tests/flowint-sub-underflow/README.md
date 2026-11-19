Test
----

Subtract from a flowint whose value is 0 and check that the result
saturates at 0 instead of wrapping around to UINT32_MAX.

sid:1 sets ``cnt`` to 0. sid:2 matches while ``cnt`` is 0 and subtracts 1,
using the ``done`` flowint so that it only happens once per flow. sid:3
checks that ``cnt`` is still 0 afterwards, and sid:4 checks that it never
becomes 4294967295.

Pcap
----

From test tls-subjectaltname. It has 68 TCP flows, so sid:2 alerts once
per flow.
