# dnp3-lua-points-repeated-index

Reading the same `points` index twice in a row must return the same
point value: the invocation-local cursor's same-position path.

The pcap carries one 16384-point group-1 variation-1 write request,
at the parser's default `max-points` bound and above the 32-point
eager threshold, so the `points` value is the lazy userdata. The
script walks `1..#points` reading `points[i]` twice per iteration and
pins both reads: non-nil, and the second read's table carries the
same `index` (the 1-based ordinal for a range object starting at 1).
This exercises the `i == cursor_pos` branch the same-index cursor
trust added; the linear-complexity evidence for that fix stays in the
MR description's timing table.

make-pcap.py ships with the test and regenerates test.pcap
(scapy; DNP3 frames are built by hand, so tshark only sees the TCP
flow).

Ticket: #9120, #9068.
