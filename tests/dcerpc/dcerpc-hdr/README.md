Tests the dcerpc.hdr sticky buffer.

The buffer exposes the 16-byte connection-oriented DCERPC header per direction:
the request-side header on to_server and the response-side header on to_client.
Uses the dcerpc-dce-iface-02 flow (bind / bind_ack / request / response) to
match each header, to confirm direction isolation (a request-header pattern must
not match on to_client), and that the whole header is inspectable (a byte at a
non-zero offset).
