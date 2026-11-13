Description
-----------

Pin the current behavior for the detection_filter keyword. In IPS mode a plain
drop rule drops the flow on match 1, so a `pass` detection_filter rule (count 3)
never trips.

Pcap: crafted with scapy
(`../detection_filter-ids-alert-tcp-stream/writepcap.py`), one TCP flow with 6
client data segments carrying "DFMATCH".

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
