# Description

ERSPAN Type II packets that cannot be decoded must raise an ERSPAN decoder
event on the GRE packet: an unsupported version, a truncated header and a
mirrored frame too short for an ethernet header.

# Ticket

https://redmine.openinfosecfoundation.org/issues/9450

# PCAP

Crafted with script.py from packet 1 of decode-erspan-typeII-01.
