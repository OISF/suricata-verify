Test
====

This is a test for the bug 5437 about 'unseen' http midstream packets.


Behavior
========

Compare with `unseen-http-stream-01`, where only the two `http` GET request
packets appear in the pcap file: the `http` stream is not seen, there (Wireshark
tags those correctly).

This test has a more complete stream (though anonymized), and Suri is able to
identify the `http` packets.

PCAP
====

Pcap was shared on Suricata's Discord server by the users who observed this
behavior.
