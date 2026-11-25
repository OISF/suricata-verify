A flowbit set by an LTE rule makes a `flowbits:isnotset` reader fail in the same update

`sid 100` (`<request_line`) sets flowbit `blocked`; `sid 200` (`<request_headers`) needs it
unset (`flowbits:isnotset,blocked`) and has its fast pattern on `http.header`. Packet 4
completes the request line and leaves the header block open, so one walk runs both, the
setter first. The pattern arrives on packet 6.

A full walk reaches 200 after the bit is set: 200 is out of the running, nothing is pending
at `request_headers`, and its default policy (`drop:flow,alert`) drops packet 4. That is
main (4badfd13f).

The regression this pins is the fail-open side of `621`: the walk decided at its start that
the reader was still in the running, because the bit was not set yet. The reader stayed
pending, its packet accept forwarded packet 4 (request line and Host header), and the flow
was only dropped on packet 6. Same fix as `621`.

Assertions: `2201001` blocked at packet 4 on `request_headers`, the default-policy drop at
packet 4, no alert from 200, flow `drop`. `gen_pcap.py` builds the pcap.
