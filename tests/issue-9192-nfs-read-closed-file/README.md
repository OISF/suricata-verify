# Redmine #9192 NFS READ continuation for a closed file

Regression test for https://redmine.openinfosecfoundation.org/issues/9192
(stable backport https://redmine.openinfosecfoundation.org/issues/9193).

## Defect

A READ reply record of at least 512 bytes whose first delivery is incomplete
takes the partial-record path: the rest of its file data is expected as a
continuation in the next deliveries, up to the end of the record given by its
record marker. The continuation looks up the file transaction of the READ's
file handle and passes its data to the file tracker of that transaction.

A complete READ reply with eof set closes the file of its transaction, but the
transaction stays in the state, and is still found by its file handle, until
it is logged and freed. If the next reply for that handle is partial, the
closed tracker stores none of the data of its first delivery, so it still
expects all of the reply's file data. The continuation was given to that
tracker, which took the rest of the record and then as many of the following
bytes as it still expected, up to the amount of file data in the first
delivery. A record that follows the reply in the same delivery and fits in
those bytes was lost without an anomaly or a parser error, and its bytes were
added to the logged size of the closed file.

This happens when the server answers the last part of a file first (readahead
with replies out of order), or when the client reads a file again just after
the eof reply closed it. With the fix, a transaction whose file is not open
cannot take the continuation: it is consumed exactly up to the end of its
record, as when no transaction is found for the handle.

## Flows

Each flow is an NFSv3/TCP connection 10.0.0.1:<port> -> 10.0.0.2:2049. The
server answers in two segments. The second segment ends with the complete
reply to the READ of a second file: 64 bytes of file data that start with
`R9192-NEXT-FILE-MARKER` (112 byte record). A LOOKUP call for
`r9192-after-<port>` and its reply follow.

readahead flows: the client sends three READ calls in one segment: offset 0
and offset 1024 (1024 bytes each) of a 1536 byte file, and the second file.
The server answers the offset 1024 READ first with a complete 560 byte reply:
512 bytes of data and eof. This last part is out of order, so the file is
closed before any of its data is stored. Then comes the reply to the offset 0
READ: a 1072 byte record with 1024 bytes of data, without eof.

reread flows: the client sends a READ call for a 600 byte file, a second READ
call for the same file from offset 0, and a READ call for the second file. The
complete 648 byte reply to the first READ (600 bytes of data, eof) closes the
file. Then comes the reply to the second READ: a 648 byte record with the same
600 bytes and eof.

| Port | Flow | Server segment 1 | Server segment 2 | Client ACKs |
| --- | --- | --- | --- | --- |
| 44101 | readahead-control | eof reply | offset 0 reply + next reply | after both segments |
| 44102 | readahead | eof reply + first 300 bytes of the offset 0 reply | its last 772 bytes + next reply | after both segments |
| 44103 | readahead-acked | as 44102 | as 44102 | after each segment |
| 44111 | reread-control | first reply | re-read reply + next reply | after both segments |
| 44112 | reread | first reply + first 300 bytes of the re-read reply | its last 348 bytes + next reply | after both segments |
| 44113 | reread-acked | as 44112 | as 44112 | after each segment |

The first 300 bytes of a split reply are its 48 header bytes and 252 bytes of
file data. The client ACKs each server segment on its own, so every segment is
delivered to the NFS parser on its own. "after both segments": the server
sends both segments before the client ACKs them. No packet to the client, on
which the closed file is logged and its transaction freed, comes between the
two deliveries, so the continuation finds the transaction with the closed
file. "after each segment": the second server segment comes between the two
deliveries, the transaction with the closed file is logged and freed, and the
continuation finds no transaction for the handle.

In the controls 44101 and 44111 the reply that follows the eof reply is
complete in the second segment, so it never takes the partial-record path.

## Expected (fixed) behavior

All flows:

- The reply to the READ of the second file is parsed: the `file.data` marker
  rule (`sid:9192201`) alerts and its file is CLOSED with 64 bytes and its
  sha256.
- The LOOKUP is logged and alerts (`sid:9192202`).
- The closed file is logged once, as the eof reply left it: CLOSED with 0
  bytes on the readahead flows, CLOSED with the 600 bytes of the first READ
  and their sha256 on the reread flows. The data of the later reply for that
  file is not extracted, as its file is already closed, the same as in the
  controls.
- No anomaly and `app_layer.error.nfs_tcp.parser` is 0.

On 44102 and 44112 the test also asserts that the closed file is not logged
with the size that includes the lost bytes (884 and 1060, see below). The raw
TCP rule `sid:9192203` confirms that the marker is on the wire in each flow.

On all builds the eof reply closes the readahead file with 0 bytes: a last
chunk that arrives out of order for a file that is not open yet closes it
before any data is stored. That is existing behavior, not part of this fix,
and the control 44101 shows it as well.

## Vulnerable behavior

On `main` @ 4badfd13f4 and `main-8.0.x` @ 08005f03ba the controls pass, and:

- 44102 and 44112: the continuation goes to the closed tracker, which still
  expects all of the reply's file data. It takes the rest of the record and
  then up to 252 more bytes, the file data of the first delivery that it did
  not take: all of the 112 byte reply to the READ of the second file. There is
  no marker alert and no file for the second READ. The closed file is logged
  with 884 bytes (readahead: 0 + 772 + 112) or 1060 bytes (reread: 600 + 348
  + 112), while its sha256 does not change. There is no anomaly and no parser
  error, and the LOOKUP still alerts: the loss is silent.
- 44103 and 44113: no transaction is found for the continuation, nothing of
  it is consumed, and it is parsed as an RPC record header. That is a fatal
  parser error (`malformed_data`, `app_layer.error.nfs_tcp.parser`) and NFS
  parsing stops for the flow: no marker alert, no file for the second READ,
  and no LOOKUP.

A fix that consumes the continuation to the end of its record when no file
transaction is found, or when the transaction's tracker never got a chunk,
but still gives it to a transaction whose file is closed, passes 44103 and
44113, and fails 44102 and 44112 as above.

## Regenerate the PCAP

The PCAP is synthetic.

```
./make-pcap.py
```

It uses Scapy and writes `input.pcap` in this directory. The output is
deterministic (fixed MACs, sequence numbers, xids and timestamps). It also
prints the per-flow table with the xids, sizes and sha256 values pinned in
`test.yaml`.
