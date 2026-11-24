# Description

Test tunnel identifiers for ERSPAN Type III: the same ICMP echo is mirrored
in two Type III sessions, which get their own tunnel ids. An erspan2 tunnel
with the same addresses and session does not match Type III traffic.

# Ticket

https://redmine.openinfosecfoundation.org/issues/8329

# PCAP

Crafted with script.py
