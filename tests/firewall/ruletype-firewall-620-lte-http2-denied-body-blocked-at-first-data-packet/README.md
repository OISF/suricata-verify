Denied host with a body: the request must be blocked at the first DATA frame, the packet
main blocks it on.

The request goes to `evil.example`, then two body DATA frames, the last with END_STREAM. A
DATA frame cannot carry the authority, so nothing that follows the request HEADERS frame can
make the allow rule match above its hook: the miss is final at the first body packet, the app
default policy decides there, and 110 must never alert.

Two earlier states of the branch got this wrong. While `http.host` read the trailer header
section, a body after a trailer could still change the answer. And while `DetectLteRevisit()`
held a sub-state rule pending until the transaction completed, the decision landed on the
frame that closed the request (8, and 10 before END_STREAM was consulted) and the body frames
before it were delivered - main drops on 6.

Assertions: no alert from 110, the blocked alert at 2201001 at `http2:stream:request_headers`
on frame 6, the flow ends `drop` and `alerted`. `gen_input_pcap.py` builds the pcap; check it
with `tshark -r input.pcap -Y http2 -T fields -e frame.number -e http2.type
-e http2.flags.end_stream -e http2.header.name` - HEADERS at 4, DATA at 6, DATA with
END_STREAM at 8.
