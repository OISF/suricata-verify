# http2-trailer-etag

A response whose only trailer field is `ETag`.

RFC 9110 section 8.8.3 says a sender MAY send `ETag` in a trailer section, so the
field must reach `http.trailer` (sid 1) and must not raise
`http2.trailer_forbidden_field` (sid 2 stays silent). The event fires for the
fields section 6.5.1 reserves for framing, routing, request modifiers,
authentication, response control data and payload processing; a validator is not
one of them.

`make-pcap.py` generates the capture: request header block at #4, response header
block at #6, response DATA at #7, the ETag trailer block at #8.
