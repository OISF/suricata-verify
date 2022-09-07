Test
====

This shows a postgresql traffic where the StartupMessage does not show the
'user' as the first parameter seen. This should be accepted, as while this is a
mandatory field, parameters may be sent in any order.

Related to bug 5524 - postgresql appproto should not error out in such a case of
parsing error.

Expected behavior
-----------------

The parser should be able to parse the StartupMessage with all its parameters.
Moreover, if it receives a complete message but sees an unkown parameter, it
should still be able to parse the following PDU.

Pcap
----

Pcap was shared by Philippe Antoine.
