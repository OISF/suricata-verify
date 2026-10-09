Same bypass attempt with the `host` field instead of `:authority`: a trailer cannot allow the flow

`618` covers the `:authority` form. This one matters separately because `http.host` falls back to
`host` only when no `:authority` was seen in the request section, so the fallback path has to apply
the same cut. The request here has no `:authority` at all (`gen_input_pcap.py` sends `host` in the
first HEADERS frame), and the trailer repeats `host` with the allowed value.

Before the fix the trailer was read like any other header, the allow rule matched above its hook,
and the flow was accepted. RFC 9110 6.5.1 keeps routing fields out of trailers, so it must not
count.

Assertions: no alert from 110, and the flow ends `drop` and `alerted`. Check the pcap with `tshark -r
input.pcap -Y http2 -T fields -e frame.number -e http2.flags.end_stream -e http2.header.name`: frame
4 has `host`, frame 8 is the trailer with `END_STREAM`.
