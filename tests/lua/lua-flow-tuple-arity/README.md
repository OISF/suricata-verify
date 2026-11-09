# lua-flow-tuple-arity

Cover test for `flow:tuple()` on a normal IPv4 flow: it must return the
6 documented values (ipver, src ip, dst ip, proto, sport, dport) for an
IPv4 flow.

The ticket's edge (a non-IP / unknown-L3 flow, where the tuple must
collapse to the single value 0) is unreachable via packet-level
reproduction: unknown-ethertype packets are dropped at decode time
(ENGINE_EVENT ETHERNET_UNKNOWN_ETHERTYPE) before any flow is created.
This pins the IP-flow contract instead. Identical behavior on the
unfixed and fixed trees (contract cover, green on both).
