Nonmatching host allowlist below `http2:stream:request_headers`, request is one HEADERS frame with
END_STREAM: the request packet itself is blocked

The request has no body and no trailer: its `:authority` is the whole of what `http.host` can ever
become for this transaction. So the rule's miss is final on that very packet, the pending accept
must not carry it, and the app default policy has to decide there.

Before the fix the rule was held pending until the *transaction* completed, which for a stream needs
both sides closed. The request stayed "open" until the response answered, and while a rule is
pending the walk appends a packet accept for the packets it holds: the decision landed on the first
response packet (packet 6 here) and the request was delivered. That is a fail-open regression of the
auto-accept notation, so this test pins the packet, not just the outcome.

What the assertions measure:

- no alert from 110, so the allow rule never matched
- the default policy's `blocked` alert at hook `http2:stream:request_headers` on packet 4
- a `drop` event for packet 4: the request itself, not the answer to it
- the flow ends `drop` and `alerted`

`gen_input_pcap.py` builds the pcap (preface, SETTINGS and one HEADERS frame with `END_STREAM` and
`END_HEADERS`, response only afterwards). Check it with `tshark -r input.pcap -Y http2 -T fields -e
frame.number -e http2.flags.end_stream -e http2.header.name`: frame 4 must show `True`.

The pair to read together is `620`, which is the same rule with a body, and `618`/`619`, where the
request closes with a trailer.
