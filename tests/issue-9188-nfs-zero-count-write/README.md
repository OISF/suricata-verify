# Redmine #9188 NFS zero-count partial WRITE desynchronizes the stream

Regression test for https://redmine.openinfosecfoundation.org/issues/9188
(stable backport https://redmine.openinfosecfoundation.org/issues/9225).

## Defect

An NFSv3 WRITE request carried in a TCP record that is 512 bytes or larger,
and whose first parser delivery is incomplete, takes the partial-record fast
path in `parse_tcp_partial_data_ts`. When the WRITE's `count` is 0,
`process_write_record` returned early, without skipping the unread tail of
the record, while the fast path reported the whole input as consumed.

The next delivery, the rest of the WRITE record, was then parsed as a new RPC
record header. That fails, and the fatal error disables NFS parsing for the
whole flow, so a later REMOVE on the flow is never parsed and NFS rules stop
matching. A complete record with the same bytes is skipped by its record
marker, so NFS parsing continues.

## Fixture

`input.pcap` is the three-flow bridge capture from the ticket (kept as-is).
Each flow sends a NULL call, a 512-byte WRITE record (76-byte header, 436
trailing bytes, `stable = 1`) and a 76-byte REMOVE whose name is
`NFSC0_CANARY_HIT`:

| Flow | Src port | Shape |
| --- | --- | --- |
| Control | 40146 | Zero-count WRITE record complete, the REMOVE in the same segment. |
| Control | 40154 | WRITE with `count = 436` split after its header, then the 436 bytes of data plus the REMOVE. |
| Attack | 56892 | Zero-count WRITE split after its header, then the 436-byte record tail plus the REMOVE. |

## Fixed expectation

- The REMOVE alert (sid 9901702) fires on **all three** flows. On the
  vulnerable build it does not fire on the attack flow.
- The raw-TCP rule (sid 9901703) shows the REMOVE bytes reach the sensor on
  every flow, independently of NFS parsing.
- No NFS anomaly and no `app_layer.error.nfs_tcp.parser`, as for the complete
  record. The vulnerable build raises `malformed_data` and one parser error
  on the attack flow.

See `issue-9188-nfs-zero-count-boundary` for the READ reply direction and
the exact record boundary.
