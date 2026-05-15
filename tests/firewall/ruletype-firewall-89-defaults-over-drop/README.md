Test that a default app-layer accept:tx policy at request-complete does not
prevent a later HTTP request-line drop from being applied.

The pcap contains a single full TCP conversation with one complete HTTP request
and response for /bar/.
