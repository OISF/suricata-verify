https://redmine.openinfosecfoundation.org/issues/8805

Reproduce loss of the configured Lua sandbox memory limit after a zero-payload
packet. The TCP handshake reaches a `needs["payload"]` Lua rule with no payload
before the client sends one byte. On affected builds, the early return discards
the configured limit. The subsequent call then has no additional allocation
headroom, so an otherwise valid 1 KB Lua allocation fails despite a configured
20 KB limit.

`input.pcap` SHA-256:
`8398f479aa47329dd3f451b0e66d3e1e782f6f80970c839729e686f3c1892a1e`
