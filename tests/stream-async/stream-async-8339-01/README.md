Test
----

Midstream pickup with ``stream.async-oneside: true`` on traffic seen in both
directions: the session is picked up (``tcp.midstream_pickups: 1``) but is not
left counted as async (``tcp.async_sessions: 0``).

Pcap
----

Reused from ``alert-testmyids-midstream3``.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8339
