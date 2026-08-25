Test that a ``suppress`` entry in threshold.config naming a firewall rule leads
to the engine erroring out, rather than silently ignoring the entry.

Fatal only at startup with ``--init-errors-fatal``, which suricata-verify always
passes. On a rule reload the same case warns and skips the entry.

Pcap: `flowbit-oring/input.pcap`, HTTP request to www.testmyids.com.
