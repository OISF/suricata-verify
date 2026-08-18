Test that a per-protocol default-policy covers a protocol's app-layer hooks
while a specific hook setting carves one of them out.

packet.default-policy opens the packet hooks. app.dns.default-policy is
drop:flow, and dns.request-started is set to accept:hook, so DNS requests are
allowed to start while every later hook falls back to the per-protocol default.

The four requests are parsed and logged, then dropped before any response
arrives. Each of the four flows accounts for two drops: one attributed to the
default app policy, and one to the flow drop that follows from it.
