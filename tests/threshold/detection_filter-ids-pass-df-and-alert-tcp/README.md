Description
-----------

Pin the current behavior for the detection_filter keyword. In IDS mode a `pass`
detection_filter rule (count 3) trips on match 4 and masks a plain alert rule
from then on, per packet.

Pcap: crafted with scapy
(`../detection_filter-ids-alert-tcp-stream/writepcap.py`), one TCP flow with 6
client data segments carrying "DFMATCH".

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
