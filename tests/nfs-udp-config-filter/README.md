# nfs-udp-config-filter

Covers `app-layer.protocols.nfs.filter` when NFS is enabled for UDP only.

The filter decides which NFS records reach EVE and applies to both
transports, but it used to be read in the TCP registration function. A
config with `nfs.tcp.enabled: no` therefore never installed it and the
built-in default (drop v3 GETATTR) stayed in place.

NFS is UDP-only here and the configured list is `read`, so READ must be
gone while WRITE and NULL, which the same run logs, must stay. Detection
is pinned as well: a logging filter changes nothing about it. Before the
fix READ is logged, so the zero-count check fails.

The capture is `nfs3-udp-high-xid`'s, referenced as
`../nfs3-udp-high-xid/input.pcap`: unmarked UDP RPC datagrams carrying a
NULL exchange, a FILE_SYNC WRITE and a READ. The run logs one response
record per procedure. With a list that names none of them (say `lookup`)
all three records appear, which is what shows a configured list replaces
the default instead of adding to it.
