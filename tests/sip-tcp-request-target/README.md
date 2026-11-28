# Description

OPTIONS and UPDATE are both SIP and HTTP/1 methods. A SIP Request-URI is an
absolute URI, so an HTTP request whose target starts with '/' or '*' must be
detected as HTTP/1 as soon as the target is seen: also when its request line
is never completed, when the method is followed by a tab, and when its
request line ends with the SIP version. A SIP request without a space after
the method must still be detected as SIP.

# PCAP

Created with `create_pcap.py`.

# Ticket

https://redmine.openinfosecfoundation.org/issues/9135
https://redmine.openinfosecfoundation.org/issues/9233
