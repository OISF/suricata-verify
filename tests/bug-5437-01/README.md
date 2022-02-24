Test
====

This is a test for the bug 5437 about unseen http midstream packets/flow.

Behavior
========

Suri seems unable to properly identify `http` traffic in this payload,
despite having `-k none` and `midstream=true` set.

Here we only have two `http` GET request packets in the pcap file: the `http`,
and the stream is not seen (Wireshark tags those correctly).

Compare with `bug-5437-02`, from which the 2 packets in the pcap from
the present test come from: the `http` stream is seen and logged there.

PCAP
====

Pcap was shared on Suricata's Discord server by the users who observed this
behavior.
