Description
-----------

Pin the current behavior for the detection_filter keyword. In IPS mode datagrams
matched by a plain pass rule are not counted by a `drop` detection_filter rule
(count 3), which trips on datagram 6.

Pcap: crafted with scapy (`../detection_filter-ips-drop-udp/writepcap.py`), 6
UDP datagrams carrying "DFMATCH"; datagrams 3 and 4 also carry "PASSME".

Ticket
------

https://redmine.openinfosecfoundation.org/issues/9416
