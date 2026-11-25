Expectation
-----------

Threat detection must leave no state behind on a packet the firewall bypassed.

The bypass is skipped for threat detection during alert finalization, but a TD
rule's post-match list runs at match time. A packet-table TD rule is evaluated
before the app-layer firewall rule that bypasses the flow, so its `xbits` setter
runs even though the packet should never have reached threat detection. The
alert is withheld; the host bit is not.

A second flow from the same host probes the bit. It must not be set.

Pcap
----

Two HTTP flows from the same client, `GET /alpha` then `GET /beta`, 100ms
apart. A short gap matters: over a multi-second gap the host entry is pruned
between flows and the probe cannot see the bit either way.

Ticket
------

Related to https://redmine.openinfosecfoundation.org/issues/8459.
