Trailer HEADERS frame naming the allowed host cannot satisfy a host allowlist hooked below
`http2:stream:request_headers`

The request goes to `evil.example`, the body is sent, and the request closes with a trailer HEADERS
frame carrying `:authority: allowed.example`. The allow rule matches `http.host`, so if the trailer
counted, the rule would match above its hook while it is held pending, its `accept:flow` would
apply, and the whole connection - body included - would go through.

HTTP/2 does not allow that: RFC 9113 8.1 forbids pseudo-header fields in trailers, and RFC 9110
6.5.1 keeps routing fields such as `Host` out of them. So `http.host` is built from the request
header section only - the frames before the first DATA frame, or before a HEADERS frame that follows
a completed block - and a trailer can never rewrite the target. This is a bypass, not a delay:
before the fix this pcap was `accept` with an `allowed` alert from 110.

Assertions: no alert from 110, and the flow ends `drop` and `alerted`. The deciding packet is not
asserted - main reaches the same outcome on a different packet, and what matters here is that the
trailer does not win.

`gen_input_pcap.py` writes the pcap; check it with `tshark -r input.pcap -Y http2 -T fields -e
frame.number -e http2.flags.end_stream -e http2.header.name` - frame 8 is the trailer, with
`:authority` and `END_STREAM` set.

`619` is the same request using the `host` field instead of `:authority`; `620` drops the trailer and
keeps the body, and `617` is the case where nothing arrives after the headers.
