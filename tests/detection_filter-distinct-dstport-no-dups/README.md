Purpose
-------
Validate that detection_filter with unique_on dst_port does not trigger when
the number of distinct destination ports stays below the threshold.

Rule requires 3 distinct destination ports for the same destination host (track by_dst).
The PCAP only has 2 distinct destination ports, so the threshold is not reached
and no alerts are expected (sid 100011).

Why this matters
---------------
Ensures duplicates or insufficient variety of dst ports do not produce alerts
when distinct counting (unique_on dst_port) is configured with a higher threshold.

Ticket: https://redmine.openinfosecfoundation.org/issues/7928

PCAP: Crafted manually to fit the test.
