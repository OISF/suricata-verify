# Redmine #9190 NFS partial-record content error is fatal

Regression test for https://redmine.openinfosecfoundation.org/issues/9190.

## Defect

An NFSv3 WRITE request carried in a TCP record that is 512 bytes or larger, and
whose first parser delivery is incomplete, takes the partial-record fast path
in `parse_tcp_partial_data_ts`. If the buffered bytes decode far enough to fail
NFS content validation (here `stable = 3`, which the parser rejects as
`stable <= 2`), the partial path returns a fatal `AppLayerResult::err()`.

A fatal application-layer error disables NFS parsing for the whole flow, in
both directions. Any later record on the flow, such as a complete LOOKUP, is
never parsed, so NFS rules stop matching even though the RPC fragment length
was already known and the parser could have skipped to the next record.

A *complete* record with the same invalid `stable = 3` is only marked
`malformed_data` and the parser advances to the next record, so subsequent NFS
inspection survives. The partial and complete paths must behave the same once
the record boundary is known.

## Fixture

`input.pcap` is the two-flow bridge capture from the ticket (kept as-is):

| Flow | Src port | Shape |
| --- | --- | --- |
| Control | 42470 | NULL, then a complete 80-byte invalid WRITE (`stable = 3`), then a LOOKUP whose name is `NFSERRMARK`. |
| Attack  | 35566 | NULL, then 72 bytes of an 804-byte WRITE record ending on the invalid `stable = 3`, then the 732-byte zero-filled record tail plus a complete LOOKUP (`NFSERRMARK`) in one segment. |

Both flows carry the literal `NFSERRMARK` to the sensor, so the raw-TCP rule
(sid 9906102) fires on both regardless of NFS state.

## Fixed expectation

- The NFS LOOKUP alert (sid 9906101) fires on **both** flows. On the vulnerable
  baseline it fires only on the control flow, because the attack flow's partial
  WRITE turned fatal before the LOOKUP.
- `nfs` `malformed_data` is still recorded exactly once on both flows (on the
  NULL call's transaction, the most recent NFS transaction when the WRITE
  fails; the server sends no NFS payload in this capture).
- No `app_layer.error.nfs_tcp.parser` is raised (the baseline raises exactly one
  on the attack flow).

The test asserts per flow by matching the client port, so the attack and
control behaviors cannot be confused. EVE records carry the direction of the
packet they are logged on: the alerts have the client as `src_port`, while the
anomaly is logged on the server ACK that triggers parsing of the to-server data
in IDS mode, so it has the client as `dest_port`.
