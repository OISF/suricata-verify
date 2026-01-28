Purpose
-------
Validate detection_filter distinct counting with unique_on src_ip.

Rule uses count 1, meaning it alerts after seeing more than 1 distinct source IP
for the same destination host (track by_dst). The PCAP contains ICMP traffic from
2 different source IPs (10.0.0.1 and 10.0.0.2) to 192.168.1.100, so the distinct
counter exceeds the threshold (2 > 1) and one alert is expected (sid 100023).

Why this matters
---------------
Introduces coverage for detection_filter unique_on src_ip behavior added in Suricata.
This test ensures that different src IPs contribute separately toward the threshold
while duplicate IPs do not. Uses ICMP to demonstrate that IP-based unique_on works
with any protocol (unlike port-based unique_on which requires tcp/udp/sctp).

Ticket: https://redmine.openinfosecfoundation.org/issues/8250

PCAP: Crafted manually to fit the test.
