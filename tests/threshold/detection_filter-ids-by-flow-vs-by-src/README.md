Description
-----------

Pin the current behavior for the detection_filter keyword. With two flows from
the same source, `track by_flow` (count 3) alerts once per flow, `track by_src`
(count 3) alerts 5 times.

Pcap: crafted with scapy (`writepcap.py`), two TCP flows from the same client
with 4 data segments each.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
