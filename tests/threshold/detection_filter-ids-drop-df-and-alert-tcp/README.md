Description
-----------

Pin the current behavior for the detection_filter keyword. In IDS mode a `drop`
detection_filter rule (count 3) alerts from match 4 on, while a plain alert rule
on the same packets alerts on all 6.

Pcap: crafted with scapy
(`../detection_filter-ids-alert-tcp-stream/writepcap.py`), one TCP flow with 6
client data segments carrying "DFMATCH".

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
