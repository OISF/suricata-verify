# lua-packet-tuple-nonip

Cover test for the `suricata.packet:tuple()` arity contract on a non-IP
packet. An ARP packet has no IP header, so `tuple()` must return a single
value (the IP version 0), not 6. This pins the arity-1 line; the behavior is
identical on the unfixed and fixed trees (contract cover, green on both).
