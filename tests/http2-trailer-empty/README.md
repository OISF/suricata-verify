# http2-trailer-empty

A request whose trailer block carries END_HEADERS|END_STREAM and no field at all.

The block is still a trailer section: the request reaches
`http2:stream:request_trailers`, so the state hook rule (sid 2) fires.

The point of the case is EVE: an empty trailer block must not log an empty
`http.request_trailers` array, because the array schemas declare `minItems: 1`.
Before the logger change the event carries `"request_trailers": []` and `run.py`
fails the test on schema validation; after it the key is absent.

`make-pcap.py` generates the capture: request header block at #4, the empty
trailer block at #9. #8 is the server's DATA frame that ends the response.
