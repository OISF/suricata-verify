Test that a default app-layer accept:tx policy at request-complete for one HTTP
transaction does not bypass firewall inspection of a later pipelined
transaction in the same packet.

The pcap contains a full TCP conversation with two pipelined HTTP requests in
one client packet: /bar/ followed by /foo/.
