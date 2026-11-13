Description
-----------

Pin the current behavior for the detection_filter keyword. In IDS mode a `drop`
detection_filter rule (count 3) alerts from match 4 on, with action `allowed`.

Pcap: crafted with scapy
(`../detection_filter-ids-alert-tcp-stream/writepcap.py`), one TCP flow with 6
client data segments carrying "DFMATCH".

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
