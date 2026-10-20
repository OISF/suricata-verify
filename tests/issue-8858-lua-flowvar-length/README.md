# Redmine #8858 Lua flowvar length validation

Regression test for https://redmine.openinfosecfoundation.org/issues/8858.

The sandboxed Lua rule uses the ticket's `fv:set("A", -1)` call on a TCP
flow. Before the fix this reached `SCMalloc(0)` and a `SIZE_MAX`-sized
`memcpy`. A fixed build rejects the requested length with a Lua error and
continues processing the packet.

Regenerate the pcap with `./make-pcap.py`.
