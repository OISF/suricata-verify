A drop verdict with JSON alert info from a dataset lookup.

`dataset:isset` with a JSON dataset and a `context_key` builds the alert info
when the lookup matches, and a `drop` rule also keeps a copy of that alert for
the drop log. Both allocations have to stay valid until the packet is logged.

The pcap is one UDP flow of 12 packets, every one of them matching the drop
rule, so the drop path with alert info runs 12 times and the packets after the
first verdict are still decoded, alerted on and recycled.
