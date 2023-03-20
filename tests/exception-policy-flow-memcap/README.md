Test
====

Test the exception policy for when Suricata reaches a flow memcap.

Expected Behavior
=================

When Suricata tries to create a new flow reaching packet 6, it will simulate a
failure, therefore dropping said packet. As midstream pickup is said to true,
Suri will later on register a midstream flow for that. Other packets/flows will
be decoded and inspected normally.

PCAP
====

Pcap from `tls` suricata-verify test.

