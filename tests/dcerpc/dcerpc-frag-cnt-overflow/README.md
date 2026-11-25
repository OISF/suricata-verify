Tests that the DCE/RPC-over-TCP fragment counter does not overflow when a
request is split over more fragments than it can count.

The pcap (see dcerpc_frag_cnt_overflow_scapy.py) is one connection carrying a
bind/bind_ack exchange followed by an opnum 11 request split over 65537
fragments with the same call id: a first fragment, 65535 middle fragments and
a last fragment, each with one byte of stub data. As many whole fragments as
fit are packed into each TCP segment to keep the pcap small. At about 1.6MB
the request is past the default stream depth, so the test disables it.

A transaction stays open until the fragment with PFC_LAST_FRAG is seen, so the
number of fragments counted on it is controlled by the traffic. The counter is
a u16. Incremented without bounds, it panics on overflow in builds with
overflow checks enabled (such as --enable-debug), and otherwise wraps around
and logs a req.frag_cnt of 1. It must saturate at 65535 instead, as the
DCE/RPC-over-UDP parser already does.
