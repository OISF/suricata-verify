Description
-----------

Pin down `detection_filter` behavior in IPS mode: a plain alert rule alerts on matches 1-4;
a `drop` detection_filter rule (count 3) drops on match 4 and the flow drop stops inspection.

Pcap: crafted with scapy (`../detection_filter-ids-alert-tcp-stream/writepcap.py`),
one TCP flow with 6 client data segments carrying "DFMATCH".

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
