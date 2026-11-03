Purpose
-------
Validate that detection_filter with unique_on dst_ip does not trigger when
the number of distinct destination IPs stays below the threshold.

Rule requires 3 distinct destination IPs for the same source host (track by_src).
The PCAP only has 2 distinct destination IPs, so the threshold is not reached
and no alerts are expected (sid 100022).

Why this matters
---------------
Ensures duplicates or insufficient variety of dst IPs do not produce alerts
when distinct counting (unique_on dst_ip) is configured with a higher threshold.

Ticket: https://redmine.openinfosecfoundation.org/issues/8250

PCAP: Crafted manually to fit the test.
