nfs3-udp-high-xid
=================

NFSv3 over UDP whose RPC transactions carry xids with the top bit set.

UDP has no record marking, but a v3 transaction can also arrive unmarked on UDP,
and the parser has to decide between the two layouts. A sniff that assumes the
marked form reads the first four bytes of the CALL header as a mark, and an xid
of `0x80000030` then claims a 48 byte record - so a high xid must not be enough
to talk the parser into the marked layout. The datagrams here are unmarked, and
each must parse as a whole transaction:

  xid 0x80000003  NULL exchange   24 bytes, under the minimum a mark would claim
  xid 0x80000030  WRITE           4096 bytes to fh 0x30
  xid 0x80000031  READ            4096 bytes from fh 0x30

Pinned: the flow is NFS, both files close with 4096 bytes, and no
`malformed_data` or `record_overflow` is raised.

`nfs3-udp-high-xid.py` writes `input.pcap` (deterministic, no dependencies);
`suricata.yaml` turns on the eve types the checks read.
