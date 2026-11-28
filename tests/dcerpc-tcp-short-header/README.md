# Description

DCERPC over TCP on a port without a probing parser, where the first segment
of the bind_ack, or of the bind, is shorter than the 16 bytes of the DCERPC
header. Protocol detection must wait for the whole header to run the DCERPC
probing parser, and detect DCERPC in both directions.

# PCAP

Created with `create_pcap.py`.

# Ticket

https://redmine.openinfosecfoundation.org/issues/9233
