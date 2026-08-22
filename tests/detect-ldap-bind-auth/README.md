# LDAP BindRequest authentication detection

Verifies the LDAP BindRequest detection keywords added for
[Redmine issue #7536](https://redmine.openinfosecfoundation.org/issues/7536):

- `ldap.bind_request.authentication:simple`
- `ldap.bind_request.authentication:sasl`
- `ldap.bind_request.sasl.mechanism`
- `ldap.bind_request.sasl.credentials`

PCAP contains three independent LDAP/TCP flows:

1. A simple BindRequest.
2. A SASL BindRequest using mechanism `GSS-SPNEGO` with credentials.
3. A SASL BindRequest using mechanism `PLAIN` without credentials.

The test checks that the authentication selector distinguishes simple and
SASL binds, that the SASL mechanism and credentials sticky buffers expose
only their respective fields, and that a SASL BindRequest with omitted
credentials is handled correctly.

The simple-authentication flow intentionally places marker strings in the
Bind DN and password that are also searched for by negative SASL-buffer
rules. Those rules must not alert. This verifies that the SASL sticky
buffers do not accidentally expose unrelated BindRequest or simple-auth
data.

## PCAP generation

The pcap was created using the scapy-based script `writepcap.py`

## Issue

Redmine: https://redmine.openinfosecfoundation.org/issues/7536
