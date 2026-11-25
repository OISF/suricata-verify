Description
-----------

Pin the current behavior for the detection_filter keyword. In IPS mode an HTTP
`drop` detection_filter rule (count 3) drops on tx 4 and drops the rest of the flow.

Pcap: crafted with scapy (`../detection_filter-ids-alert-http/writepcap.py`), one keep-alive HTTP/1.1 flow with 6 `GET /df` requests.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
