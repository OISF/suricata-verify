# Description

Tests that alerts for the pgsql app-proto will include pgsql app-proto metadata,
in IPS mode.

As this test uses a stream rule, in IPS mode the engine generating two alerts is
expected.

## PCAP

Pcap file reused from pgsql-ssl-rejected-md5-auth-simple-query

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/6983
https://redmine.openinfosecfoundation.org/issues/7000
