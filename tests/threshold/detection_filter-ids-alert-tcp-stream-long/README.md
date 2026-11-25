Description
-----------

Pin the current behavior for the detection_filter keyword. In IDS mode a `tcp`
detection_filter rule (count 3) counts raw stream inspections, not segments: 7
inspections give 4 alerts (chunk-size randomization disabled to keep the
inspection count fixed).

Pcap: crafted with scapy (`writepcap.py`), one TCP flow with 40 client data
segments of 500 bytes.

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
