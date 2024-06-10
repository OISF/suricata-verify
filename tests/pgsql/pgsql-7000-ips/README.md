# Description

Showcase engine behavior with simple pgsql stream rules and alert metadata, in
IPS mode.

## Behavior

The 2 rules will match on the PGSQL queries for `SELECT` (sid 1) and `DELETE FROM`,
(sid 2). However, the combination of IPS mode matching on the traffic as soon as
the engine sees it with the continuously available stream buffer leads to way
more matches than could be initially expected. The `payload_printable` EVE field
was left to illustrate this.

## Pcap

This test uses the pcap from PGSQL test `pgsql-simple-query-rollback`

## Redmine ticket

Partly related to:
https://redmine.openinfosecfoundation.org/issues/7000
