# Stream reassembly depth and ACK tracking

A long upload in IPS mode that runs well past `stream.reassembly.depth`.

Once a direction hits the reassembly depth it stops collecting data, and with
that its `base_seq` - the sequence number the reassembly buffer starts at - stops
moving. The stream keeps carrying bytes, so at some point the ACK's of the peer
are more than 2^31 bytes past that frozen anchor. `SEQ_GT()` compares inside half
of the sequence space, so it then reads such an ACK as being *behind* `base_seq`
and refuses to update `last_ack` (the bound is there to reject ACK's that cannot
be real, see Redmine #6865). `last_ack` freezes, `next_win` freezes with it, and
every packet of the flow from then on is flagged out-of-window or invalid-ACK
until the sequence space comes all the way round 2^32 bytes later - at which
point `last_ack` takes a step of 4 GB in one go and the reassembly engine
declares a gap that never happened. In IPS mode an app-layer that cannot skip
gaps (TLS) turns that into an "applayer error" and the exception policy drops
the flow without an RST or FIN. The reported drop lands at 2^32 + 2^31 + depth
bytes into the stream, see Redmine #9141.

This test pins the reachable part: reassembly does stop at the depth
(`tcp.stream_depth_reached`), the data before it does reach the app-layer (the
HTTP request line is parsed), and the rest of the flow stays clean - no gap, no
out-of-window packet, no invalid ACK, no drop.

## Ticket

https://redmine.openinfosecfoundation.org/issues/9141

## Limits

The arithmetic that needs 2^31 bytes of a stream cannot be crossed with a pcap
that small, so this is a regression guard, not a reproducer: it also passes
without the fix. The wrap itself is pinned by the unit tests
`StreamTcpTest46`/`StreamTcpTest47` in `src/tests/stream-tcp.c`, which set the
sequence numbers of a stream that went 2^31 bytes past its depth directly.

## Pcap

Generated for this test: a 3-way handshake, then an HTTP POST with a 40 KB body
in 1000 byte segments against an 8 KB depth. The server sends small responses
and ACK's every second segment, so both directions keep their sequence numbers
in the normal relationship to each other.
