Same bypass attempt with the `host` field instead of `:authority`: a trailer cannot allow the flow

`618` covers the `:authority` form. This one matters separately because `http.host` falls back to
`host` only when no `:authority` was seen in the request section, so the fallback path has to apply
the same cut. The request here has no `:authority` at all (`gen_input_pcap.py` sends `host` in the
first HEADERS frame), and the trailer repeats `host` with the allowed value.

Before the fix the trailer was read like any other header, the allow rule matched above its hook,
and the flow was accepted. RFC 9110 6.5.1 keeps routing fields out of trailers, so it must not
count.

Assertions: no alert from 110, the blocked alert at 2201001 on frame 6 (where main decides
too), and the flow ends `drop` and `alerted`. Check the pcap with `tshark -r
input.pcap -Y http2 -T fields -e frame.number -e http2.flags.end_stream -e http2.header.name`: frame
4 has `host`, frame 8 is the trailer with `END_STREAM`.
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
