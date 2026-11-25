Description
-----------

Pin the current behavior for the detection_filter keyword. In IPS mode a UDP
`drop` detection_filter rule (count 3) drops datagrams 4-6 one by one, without a
flow drop.

Pcap: crafted with scapy (`writepcap.py`), 6 UDP datagrams carrying "DFMATCH";
datagrams 3 and 4 also carry "PASSME".

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
