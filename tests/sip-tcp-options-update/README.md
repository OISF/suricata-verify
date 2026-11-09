# Description

OPTIONS and UPDATE are both SIP and HTTP/1 methods. SIP requests over TCP
using them must be detected as SIP, also when the request line is split
across segments or sent byte by byte, and HTTP requests using them must stay
HTTP, including requests with "SIP/" in the URI or in a header. NOTIFY, also
probed, is split the same way.

Both the SIP and HTTP patterns used to match these requests, triggering a
debug validation assertion in protocol detection.

# PCAP

Created with `create_pcap.py`.

# Ticket

https://redmine.openinfosecfoundation.org/issues/9135
https://redmine.openinfosecfoundation.org/issues/9233
