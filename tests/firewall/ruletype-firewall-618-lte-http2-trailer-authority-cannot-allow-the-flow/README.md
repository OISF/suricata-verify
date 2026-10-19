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

The http2 default policy is `accept:hook`, not `drop:flow`: with `drop:flow` the flow ends on
packet 6, the first DATA frame, and the trailer at packet 8 is never reached, so the test passes
with or without the change it pins. With `accept:hook` the request outlives the DATA frame and the
trailer update is the last thing that could still decide it.

What the test claims is only that: the allow rule must not fire at any packet. Reverting the
request-header-section change to `http.host` makes sid 110 alert on packet 8 and the flow end
accepted, which is the bypass, so the filter is a witness and not a guard. The packet at which a
hook-scope default policy logs is deliberately not asserted here: on the musl and msys2 CI legs it
does not land on the packet the glibc legs show, and that difference is about where an alert is
attributed, not about what the firewall decides. `560` and `608` are the pins for the re-inspection
mechanism itself.
