Description
-----------

Pin the current behavior for the detection_filter keyword. An HTTP
detection_filter rule (count 3) counts transactions and alerts on txs 3-5; a
plain rule alerts on all 6.

Pcap: crafted with scapy (`writepcap.py`), one keep-alive HTTP/1.1 flow with 6
`GET /df` requests.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
