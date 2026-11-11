Description
-----------

Pin the current behavior for the detection_filter keyword. In IPS mode a plain
UDP drop rule drops datagrams 1-3; from datagram 4 a `pass` detection_filter
rule (count 3) trips and masks it.

Pcap: crafted with scapy (`../detection_filter-ips-drop-udp/writepcap.py`), 6
UDP datagrams carrying "DFMATCH"; datagrams 3 and 4 also carry "PASSME".

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
