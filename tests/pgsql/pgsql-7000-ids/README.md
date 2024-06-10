# Description

Showcase engine behavior with simple pgsql stream rules and alert metadata.

## Behavior

The 2 rules will match on the PGSQL queries for `SELECT` (sid 1) and `DELETE FROM`,
(sid 2) with one extra alert for sid 1 due to the portion of the stream
containing the last seen SELECT after the real message was seen.

## Pcap

This test uses the pcap from PGSQL test `pgsql-simple-query-rollback`

## Redmine ticket

Partly related to:
https://redmine.openinfosecfoundation.org/issues/7000
