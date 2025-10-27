Purpose
-------
Validate detection_filter distinct counting with unique_on src_port.

Rule uses count 1, meaning it alerts after seeing more than 1 distinct source port
for the same source host (track by_src). The PCAP contains traffic with 2 different
source ports toward 2.2.2.2:80, so the distinct counter exceeds the threshold (2 > 1)
and one alert is expected (sid 100002).

Why this matters
---------------
Introduces coverage for detection_filter unique_on src_port behavior added in Suricata.
This test ensures that different src ports contribute separately toward the threshold
while duplicate ports do not.

Ticket: https://redmine.openinfosecfoundation.org/issues/7928

PCAP: Crafted manually to fit the test.
