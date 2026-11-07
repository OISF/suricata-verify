# nfs-tcp-record-mark-overflow

RFC 5531 11 makes the RPC record mark a 31 bit byte count for every NFS
version. One v3 CALL on a TCP session to 2049 claims 1 GiB with 100 bytes
behind it. The engine has to abandon the flow with the `record_overflow`
event rather than buffer toward the claim, and it must not turn the record
into an NFS transaction.

`test.rules` carries the `record_overflow` alert rule (sid 2223010) so the
alert metadata path is exercised too: the alert must not gain an `nfs` or
`rpc` block describing a call that was never parsed.

`nfs-tcp-record-mark-overflow.py` regenerates `input.pcap`.
