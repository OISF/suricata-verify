Test that a ``threshold`` entry in threshold.config naming a firewall rule leads
to the engine erroring out. Covers the SetupThresholdRule path, which handles
``threshold``, ``event_filter`` and ``rate_filter``.

Pcap: `flowbit-oring/input.pcap`, HTTP request to www.testmyids.com.
