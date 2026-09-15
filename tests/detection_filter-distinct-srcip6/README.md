Purpose
-------
Validate detection_filter distinct counting with unique_on src_ip for IPv6 addresses.

Rule uses count 1, meaning it alerts after seeing more than 1 distinct source IPv6
address for the same destination host (track by_dst). The PCAP contains ICMPv6 traffic
from 2 different source IPs (2001:db8::1 and 2001:db8::2) to 2001:db8::100, so the
distinct counter exceeds the threshold (2 > 1) and one alert is expected (sid 100026).

Why this matters
---------------
Ensures that the unique_on src_ip feature works correctly with IPv6 addresses.
This validates that the hash table tracking mechanism handles 128-bit IPv6 addresses
properly.

Ticket: https://redmine.openinfosecfoundation.org/issues/8250

PCAP: Crafted manually to fit the test.
