Test
----

A simple scenario:

Startup phase
Two SELECT query statements (one right after a TPC gap)

The traffic ends without a proper connection termination.

Expectation
-----------

The accompanying alert rule on pgsql.query `SELECT`, should fire twice.

Pcap
----

Crafted with scapy mainly by Claude, with guidance, based on traffic description
from the ticket. See writepcap.py

Ticket
------

https://redmine.openinfosecfoundation.org/issues/8822
