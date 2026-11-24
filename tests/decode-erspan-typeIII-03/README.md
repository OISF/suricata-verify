# Description

ERSPAN Type III with the O flag set, so every packet carries the 8 byte
platform specific sub-header, and with VLAN 23 in the ERSPAN header. The
mirrored session must still be decoded, and its events must carry the VLAN.

# Ticket

https://redmine.openinfosecfoundation.org/issues/8329

# PCAP

Crafted with script.py from decode-erspan-typeIII-01.
