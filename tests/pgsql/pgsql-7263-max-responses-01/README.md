Purpose
-------

Cover the minimum configurable value for pgsql.max-responses.

`max-responses` is set to 21 here.

What grows `tx.responses`
-------------------------

DataRow messages are folded into a single `ConsolidatedDataRow` when CommandComplete
arrives, so `SELECT * FROM huge_table` costs two entries no matter how many
rows come back. What grows the vector is the number of separate backend
*messages* in one transaction, and the startup sequence is where the protocol
itself invites a long run of them:

    AuthenticationOk -> ParameterStatus * N -> BackendKeyData -> ReadyForQuery

A real server could report a dozen or so parameter status there.

Scenario
--------

Four flows, differing only in how many parameters the backend reports. Each
carries a distinct BackendKeyData pid, so one filter can target one flow and
say whether that message was stored or refused. More details are written in the scapy script.

Pcap
----

Crafted by Claude, using scapy, some guidelines and guidance and ticket info.

See `writepcap.py`.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/7263
