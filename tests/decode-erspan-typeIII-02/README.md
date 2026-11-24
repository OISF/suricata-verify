# Description

ERSPAN Type III packets that cannot be decoded must raise an ERSPAN decoder
event on the GRE packet: an unsupported frame type, an unsupported version,
a truncated header or platform specific sub-header, and a mirrored frame too
short for an ethernet header.

# Ticket

https://redmine.openinfosecfoundation.org/issues/8329

# PCAP

Crafted with script.py from packet 1 of decode-erspan-typeIII-01.
