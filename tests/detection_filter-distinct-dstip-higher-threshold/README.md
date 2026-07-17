Purpose
-------
Validate detection_filter distinct counting with unique_on dst_ip using a higher
threshold (count 3).

Rule uses count 3, meaning it alerts after seeing more than 3 distinct destination IPs
for the same source host (track by_src). The PCAP contains ICMP traffic from 10.0.0.1
to 4 different destination IPs (192.168.1.1 through 192.168.1.4), plus one duplicate,
so the distinct counter exceeds the threshold (4 > 3) and one alert is expected
(sid 100027).

Why this matters
---------------
Complements the count-1 test by verifying that higher thresholds work correctly:
the engine must accumulate enough distinct IPs before alerting, and duplicates
must not inflate the count.

Ticket: https://redmine.openinfosecfoundation.org/issues/8250

PCAP: Crafted manually to fit the test.
