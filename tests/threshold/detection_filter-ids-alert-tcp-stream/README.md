Description
-----------

Pin the current behavior for the detection_filter keyword. In IDS mode the raw
stream of a short flow is inspected once, so a `tcp` detection_filter rule
(count 3) never alerts.

Pcap: crafted with scapy (`writepcap.py`), one TCP flow with 6 client data
segments carrying "DFMATCH".

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
