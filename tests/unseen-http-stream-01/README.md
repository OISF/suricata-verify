Test
====

This is a test for the bug 5437 about 'unseen' http midstream packets.


Behavior
========

Suri seems unable to properly identify `http` traffic in this payload,
despite the `-k none` argument.

Compare with `unseen-http-stream-02`, from which the 2 packets in the pcap from
the present test come from: the `http` stream is logged, there.

PCAP
====

Pcap was shared on Suricata's Discord server by the users who observed this
behavior.
