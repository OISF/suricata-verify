# Description

Tests that alerts for the pgsql app-proto will include pgsql app-proto metadata.

This shows what might be a bug - more investigation is needed: that we may be
logging not the transaction that triggered the alert itself, but maybe the
subsequent one - or none, if the alert was triggered with the last seen message
for PGSQL.

## PCAP

Pcap file reused from pgsql-ssl-rejected-md5-auth-simple-query

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/6983
