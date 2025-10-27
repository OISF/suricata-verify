Purpose
-------
Validate detection_filter distinct counting with unique_on dst_port.

Rule requires 1 distinct destination port for the same destination host (track by_dst).
The PCAP contains traffic that hits 2 different destination ports to 1.1.1.1,
so the distinct counter reaches the threshold and one alert is expected (sid 100001).

Why this matters
---------------
Introduces coverage for detection_filter unique_on dst_port behavior added in Suricata.
This test ensures that different dst ports contribute separately toward the threshold
while duplicate ports do not.

Ticket: https://redmine.openinfosecfoundation.org/issues/7928

PCAP: Crafted manually to fit the test.
