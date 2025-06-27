Purpose
-------
Validate that pcap-file.delete-when-done=non-alerts deletes the input PCAP
when no alerts are generated.

No rules file is provided (detection disabled via custom suricata.yaml), so
Suricata processes the PCAP without generating any alerts. Since no alerts are
present, the PCAP file must be deleted.

The original PCAP is stored as input_origin.pcap and copied to input.pcap
before each run via the setup script, so re-runs work correctly.

Ticket: https://redmine.openinfosecfoundation.org/issues/7786
