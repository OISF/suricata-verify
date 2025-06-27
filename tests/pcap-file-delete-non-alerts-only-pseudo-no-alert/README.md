Purpose
-------
Validate that pcap-file.delete-when-done=non-alerts deletes the input PCAP
when only pseudo-packets (no real alerts) are generated.

The rule is a pass rule that matches TLS traffic but does not generate alerts.
Even though Suricata processes the flow and generates pseudo-packets for flow
cleanup, no actual alerts are raised. Since no alerts are present, the PCAP
file must be deleted.

The original PCAP is stored as input_origin.pcap and copied to input.pcap
before each run via the setup script, so re-runs work correctly.

Ticket: https://redmine.openinfosecfoundation.org/issues/7786
