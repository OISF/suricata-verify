Test
----

Midstream pickup on a FIN packet with payload, with ``stream.async-oneside: true``:
the session is counted as async (``tcp.async_sessions: 1``).

Pcap
----

Packet 4 (FIN/PSH/ACK, 86 bytes of payload) of
``stream-async/http/stream-async-6063-srv-01/http-request-header-async-srv.pcap``,
extracted with ``editcap``.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8339
