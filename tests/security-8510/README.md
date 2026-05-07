# Security 8510

Purpose: exercise defrag with forced hash collisions (`defrag.hash-size=1`) using a mixed IPv4/IPv6 fragmented packet spray. The test passes if Suricata processes the pcap without crashing.

PCAP: `defrag-af-confusion-spray-h8.pcap`, provided in ticket 8510, and
generated with scripts in that ticket.

SHA256: `68b362406904a64b1349d080af3b837f0420973908553cdf9378d001e87ea1ab`.

Ticket: https://redmine.openinfosecfoundation.org/issues/8510
