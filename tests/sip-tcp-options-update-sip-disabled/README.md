# Description

With SIP disabled, requests using OPTIONS and UPDATE, methods shared by SIP and
HTTP/1, are detected as HTTP/1 over TCP, whether they are HTTP requests or SIP
requests. HTTP/1 detection must not depend on SIP being enabled.

# PCAP

From the sip-tcp-options-update test.

# Ticket

https://redmine.openinfosecfoundation.org/issues/9135
