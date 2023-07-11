# Test and Showcase the Verdict Field in IPS mode

Showcase how a given packet may trigger ``alert`` rules and have a ``verdict``
``drop`` or ``reject`` due to other rules or events.

# Behavior

For pcap_cnt 13, we'll see three events related to the same packet, one alert from
an ``alert`` rule (sid: 1), another for a ``drop`` rule (sid: 3) and finally the
``drop`` event. The verdict, in all three cases, will be ``drop``, due to rule
sid 3.

We should also see ``alert`` and ``drop`` associated with sid 2, which is a
reject rule for the ICMP protocol.


# Pcap

Comes from the test `decode-teredo-01` as it has a good variety of protocols.
