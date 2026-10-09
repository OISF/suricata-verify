Denied host with a body: the flow is dropped, but the frames before the request closes are delivered

The request goes to `evil.example`, then two body DATA frames, the last with END_STREAM. A body
cannot carry the authority, so once the trailer reading is fixed there is nothing left that could
make this rule match above its hook: the flow must end `drop` and 110 must never alert. Both hold.

What is *not* fixed is when. The rule is still held pending until the request side closes - that is
what the revisit exists for, to cover the header-list buffers that a trailer really can rewrite - so
the packet accept for a pending rule keeps covering the body: the decision lands on packet 8, the
END_STREAM frame, where main decides on packet 6. The frames of a denied request can therefore reach
the server before it is dropped.

The deciding packet is deliberately not asserted here, because this is the open part of the design
and not a property the branch claims. Closing it means making the revisit buffer-aware: a rule whose
patterns sit only in buffers that the header section already completed should be final at its hook,
and only a rule with a header-list buffer should stay revisitable. That needs a per-buffer flag at
registration, so it is not part of this change. See the limitations section of
`doc/userguide/firewall/firewall-design.rst`.

Assertions: no alert from 110, flow ends `drop` and `alerted`. `gen_input_pcap.py` builds the pcap;
`tshark -r input.pcap -Y http2 -T fields -e frame.number -e http2.type -e http2.flags.end_stream`
shows HEADERS at 4, DATA at 6 and the closing DATA at 8.

`617` is this rule with no body at all, where the request itself is blocked, and `618`/`619` are the
same traffic with a trailer that tries to name the allowed host.
