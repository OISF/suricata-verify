Test
====

Showcase PGSQL events for truncated messages. This test will have an alert due
to a `DataRow` message that has its contents split over more than one PGSQL
message, leading to a TruncatedMessage event.

Pcap
====

Pcap comes from PGSQL test for 5000 queries
