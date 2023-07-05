# Test Address Lists

Test various combinations of address lists.

## PCAP

The PCAP was created with real live traffic and contains 4 HTTP
requests for "GET /suricata.html" with the following address
combinations:

- 10.16.1.11 -> 10.16.1.10
- 10.16.1.11 -> 10.16.1.100
- 10.16.1.11 -> 10.16.2.100
- 10.16.1.11 -> 35.212.0.44 (suricata.io)

## Related Issues

- https://redmine.openinfosecfoundation.org/issues/608
