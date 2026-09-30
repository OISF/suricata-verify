A drop verdict with JSON alert info from a pcre capture.

`pcre:"/.../,alert:<name>"` builds the alert info from the captured group, and
a `drop` rule also keeps a copy of that alert for the drop log. Both
allocations have to stay valid until the packet is logged.

The pcap is one UDP flow of 12 packets, each carrying a different value for the
capture and every one of them matching the drop rule, so the drop path with
alert info runs 12 times and the packets after the first verdict are still
decoded, alerted on and recycled.
