# LDAP BindRequest version detection

Verifies the LDAP BindRequest detection keyword added for
[Redmine issue #7536](https://redmine.openinfosecfoundation.org/issues/7536):

- `ldap.bind_request.version`

PCAP contains three independent LDAP/TCP flows with BindRequest versions 1,
3, and 127.

The test checks that the version keyword matches each encoded version exactly.
A negative rule for version 2 must not alert.

## PCAP generation

The pcap was created using the scapy-based script `writepcap.py`

## Issue

Redmine: https://redmine.openinfosecfoundation.org/issues/7536
