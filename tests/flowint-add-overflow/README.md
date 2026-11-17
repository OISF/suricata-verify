Test
----

Add to a flowint so that the result would exceed UINT32_MAX and check that
the result saturates at UINT32_MAX instead of wrapping around.

sid:1 sets ``cnt`` to 4294967294. sid:2 adds 5 to it, using the ``done``
flowint so that it only happens once per flow. sid:3 checks that ``cnt`` is
4294967295 afterwards, and sid:4 checks that it never wraps to a small value.

Pcap
----

From test tls-subjectaltname. It has 68 TCP flows, so sid:2 alerts once
per flow.
