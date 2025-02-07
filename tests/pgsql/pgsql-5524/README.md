# Test Description

Check that pgsql app-proto parser is able to keep parsing even if it encounters
unknown bodies, to consume known further PDUs.

## PCAP

PCAP extracted from a larger sample capture found on
https://wiki.wireshark.org/PostgresProtocol: pgsql-jdbc.

## Related issues

https://redmine.openinfosecfoundation.org/issues/5524
