Test
====

Test both the exception policy for when Suricata reaches a flow memcap, and the
command-line option to simulate said memcap hit.

Expected Behavior
=================

When Suricata tries to create a new flow reaching packet 6, it will simulate a
failure, therefore dropping said packet. As midstream pickup is set to true,
Suri will later on register a midstream flow for that. Other packets/flows will
be decoded and inspected normally.

Please note that there will be no exception-policy output associated with the
``flow`` event for the flow-memcap, as in this scenario the engine wasn't able
to get a new flow. (Cf ticket #7884 - https://redmine.openinfosecfoundation.org/issues/7884)

PCAP
====

Pcap from `tls` suricata-verify test.

