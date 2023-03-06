Description
===========
Test corresponding to fix for the behavior of `base64_decode` keyword in case an
invalid character is encountered.
For handling of such cases, [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648#section-3.3) has been taken into account.

PCAP
====
PCAP comes from the redmine ticket [5223](https://redmine.openinfosecfoundation.org/issues/5223)

Redmine ticket
==============
https://redmine.openinfosecfoundation.org/issues/5223

Reported by
===========
Brandon Murphy
