Purpose
-------
Validate detection_filter distinct counting with unique_on dst_ip.

Rule uses count 1, meaning it alerts after seeing more than 1 distinct destination IP
for the same source host (track by_src). The PCAP contains ICMP traffic from 10.0.0.1
to 2 different destination IPs (192.168.1.1 and 192.168.1.2), so the distinct counter
exceeds the threshold (2 > 1) and one alert is expected (sid 100021).

Why this matters
---------------
Introduces coverage for detection_filter unique_on dst_ip behavior added in Suricata.
This test ensures that different dst IPs contribute separately toward the threshold
while duplicate IPs do not. Uses ICMP to demonstrate that IP-based unique_on works
with any protocol (unlike port-based unique_on which requires tcp/udp/sctp).

Ticket: https://redmine.openinfosecfoundation.org/issues/8250

PCAP: Crafted manually to fit the test.
