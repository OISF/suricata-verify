Purpose
-------
Validate that detection_filter with unique_on src_ip does not trigger when
the number of distinct source IPs stays below the threshold.

Rule requires 3 distinct source IPs for the same destination host (track by_dst).
The PCAP only has 2 distinct source IPs, so the threshold is not reached
and no alerts are expected (sid 100024).

Why this matters
---------------
Ensures duplicates or insufficient variety of src IPs do not produce alerts
when distinct counting (unique_on src_ip) is configured with a higher threshold.

Ticket: https://redmine.openinfosecfoundation.org/issues/8250

PCAP: Crafted manually to fit the test.
