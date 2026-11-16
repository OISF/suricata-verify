A flowbit set and read by LTE rules in the same update

`sid 100` (`<request_line`) sets flowbit `ok`; `sid 200` (`<request_headers`) reads it with
`flowbits:isset,ok` and has its fast pattern on `http.header`. Packet 4 completes the request
line and leaves the header block open, so one walk runs both: the setter first (lower id),
then the reader at its own hook with its pattern still missing. The pattern arrives on
packet 6.

A full walk reaches 200 after 100 has set the bit, finds it pending (its buffer can still
grow) and holds the `request_headers` default: 200 matches on packet 6 and accepts the flow.
That is main (4badfd13f).

The regression this pins: when the fast pattern leaves a reader out of the list, the walk
decides at its start whether the rule is still in the running. It ran the reader's packet
conditions there, before the setter had acted, so the reader was rejected, nothing was
pending, and the setter's match applied the `request_headers` default on packet 4
(`2201001` blocked, flow dropped). Fixed by giving LTE rules that read a variable no
prefilter, so they are in the list and inspected in order.

`622` is the mirror case, a reader that requires the bit unset.

Assertions: 200 `allowed` at packet 6 on `request_headers`, no drop, flow `accept`.
`gen_pcap.py` builds the pcap.
