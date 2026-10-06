# nfs3-udp-only-write-toolarge

NFS limit settings must be loaded from the config by the UDP parser
registration, not only by the TCP one.

The capture is the same UDP capture as `nfs3-udp-write-toolarge`
(a `LOOKUP` datagram followed by a single 64512-byte `WRITE` datagram
on a port Suricata does not probe), but the test config disables the
NFS TCP parser (`nfs.tcp.enabled: no`) and lowers
`app-layer.protocols.nfs.max-write-size` to 49152, below the 64512
datagram. Before the UDP registration loaded the shared limit settings
(only `max-tx` was read there), the default 16 MiB limit applied and
the oversized WRITE was never rejected. With the fix the WRITE is
rejected at the shared size check and
`anomaly.event: write_request_too_large` is raised, and the datagram
itself is still well formed.
