# Description

Decode an HTTP session mirrored with ERSPAN Type III (GRE protocol type
0x22EB). The flow, the HTTP transaction and an alert must come from the
mirrored traffic.

# Ticket

https://redmine.openinfosecfoundation.org/issues/8329

# PCAP

From the ERSPAN Type III test by Gianni Tedesco in
OISF/suricata-verify#2946, converted to the classic microsecond pcap format,
which libpcap on OpenBSD can read.
