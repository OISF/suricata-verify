# dnp3-lua-points-pairs

`pairs()` over a DNP3 object's `points` value must walk the lazy
userdata the same way the plain table is walked.

Request 1 of the pcap carries a 33-point group-1 variation-1 object
(above the 32-point eager threshold, so `points` is the lazy
userdata); request 2 carries a 32-point object of the same shape
(`points` is the plain table copy). The script runs the same
`for i, p in pairs(obj.points)` loop over both and pins the contract:
the iteration yields `(position, point table)` for `1..#points`, keys
arrive in order, and every point table carries `index == key` (for a
range object starting at 1 the point index is the 1-based ordinal).

Before the `__pairs` fix the lazy value had no `__pairs` metamethod,
so the 33-point loop raised and only the 32-point alert fired; the
`33 lazy count=33 ok` stdout line is absent on unfixed code.

make-pcap.py ships with the test and regenerates test.pcap
(scapy; DNP3 frames are built by hand, so tshark only sees the TCP
flow).
