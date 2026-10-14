# Redmine #9194 NFS partial record tail after the file data

Regression test for https://redmine.openinfosecfoundation.org/issues/9194
(stable backport https://redmine.openinfosecfoundation.org/issues/9195).

## Defect

An NFSv3 WRITE call or READ reply record of at least 512 bytes whose first
delivery is incomplete takes the partial-record path: the file data still
missing is expected as a continuation in the next deliveries. The RPC record
marker gives the end of the record, and the record can hold more bytes after
the file data and its XDR padding (the record tail). All of these bytes belong
to the record, so the continuation must consume exactly them, whether they
arrive with the end of the file data or later, and must never parse them as
an RPC record.

On the vulnerable build the continuation ends with the file data and its
padding, and the record tail is parsed as RPC records:

- A tail that holds a complete RPC record is processed as if it had been sent
  on its own. A LOOKUP call in the tail of a WRITE is logged and alerts. A
  READ reply in the tail of a READ reply is stored as the file of the READ it
  answers, and that READ's request is used up, so its real reply is ignored.
- A tail that is not an RPC record (zeros) is a fatal parser error, and NFS
  parsing stops for the rest of the flow.

A partial READ reply whose first delivery already holds all of its file data
has only padding left for the continuation. Its READ is answered at that
point and must be removed from the request map, as when a continuation
completes the data. Otherwise a later reply with the same xid is processed as
a READ reply and logged as a second file. On the vulnerable build these flows
fail earlier: the padding left after the data is parsed as the start of an
RPC record.

That padding is only owed to a file that is still open. A partial READ reply
can be a re-read of a handle whose file is already closed, for example by a
complete reply with eof set to an earlier READ. It has no open file to go to,
so its data is not stored, and the padding left after its data must be
consumed without being counted as data of the closed file. On the vulnerable
build that padding is parsed as the start of an RPC record as well.

## Flows

Each case is an independent NFSv3/TCP flow (one client source port). Every
data segment is ACKed by the peer, so Suricata delivers each segment to the
NFS parser on its own. A record delivery of "300" is the first 300 bytes of
the record: the RPC and NFS headers and part of the file data.

WRITE flows (to server): an UNSTABLE WRITE at offset 0, then a LOOKUP for
`REAL-<port>` (same size as a LOOKUP tail), a LOOKUP for `LAST-<port>`, and a
COMMIT that closes the file, each in its own delivery unless noted. A LOOKUP
tail is a complete LOOKUP call for `FAKE-<port>` (96 bytes).

| Port | Flow | Data (pad) | Record tail | Deliveries of the WRITE record |
| --- | --- | --- | --- | --- |
| 41000 | w-control | 600 (0) | none | 300 \| rest of data |
| 41001 | a | 600 (0) | LOOKUP | 300 \| rest of data + tail |
| 41002 | b | 600 (0) | LOOKUP | 300 \| rest of data \| tail |
| 41003 | c | 600 (0) | 96 zero bytes | 300 \| rest of data + tail |
| 41004 | split | 600 (0) | LOOKUP | 300 \| rest of data + first 48 tail bytes \| last 48 tail bytes + REAL LOOKUP |
| 41005 | w-whole (control) | 600 (0) | LOOKUP | the complete record |
| 41010 | w-control-pad3 | 601 (3) | none | 300 \| rest of data + pad |
| 41011 | a-pad3 | 601 (3) | LOOKUP | 300 \| rest of data + pad + tail |

READ flows (to client): three pipelined READ calls for three handles, then
the reply to the first READ (eof), the real reply to the second READ (64 bytes
starting with `READMARKER`), the reply to the third READ (64 bytes starting
with `LASTMARKER`), and a LOOKUP call. A reply tail is a complete reply to the
second READ (64 bytes starting with `FAKEMARKER`, the same size as the real
reply), sent while that READ is still outstanding.

| Port | Flow | Data (pad) | Record tail | Deliveries of the first reply |
| --- | --- | --- | --- | --- |
| 42000 | r-control | 600 (0) | none | 300 \| rest of data |
| 42001 | d | 600 (0) | reply | 300 \| rest of data + tail |
| 42002 | d-own | 600 (0) | reply | 300 \| rest of data \| tail |
| 42003 | r-whole (control) | 600 (0) | reply | the complete record |
| 42010 | r-control-pad3 | 601 (3) | none | 300 \| rest of data + pad |
| 42011 | d-pad3 | 601 (3) | reply | 300 \| rest of data + pad + tail |

Duplicate reply flows (to client): a READ call for 501 bytes, its 552-byte
reply (501 data bytes, 3 pad bytes, eof) in two deliveries, then a second
reply with the same xid (64 bytes starting with `DUPMARKER`), and a LOOKUP
call.

| Port | Flow | Deliveries of the first reply |
| --- | --- | --- |
| 43000 | e-control | cut 100 bytes before the end, inside the data |
| 43001 | e | all data + 1 pad byte \| last 2 pad bytes |
| 43002 | e-pad0 | all data, ending on the last data byte \| 3 pad bytes |

Closed file flows (to client): two READ calls for the same handle, and a READ
call for a second handle. The first server segment holds the complete eof
reply to the first READ (601 data bytes, 3 pad bytes), which closes the file,
then the start of the reply to the second READ, the re-read (601 other data
bytes, 3 pad bytes, eof). The second segment holds the rest of the re-read
reply and the reply to the third READ (64 bytes starting with `READMARKER`).
A LOOKUP call follows. The client ACKs both segments only after the second
one is sent: a file sent to the client is logged on a packet to the client,
so no such packet comes between the two deliveries and the closed file is
still unlogged when the second delivery is parsed. Were each segment ACKed
before the next one is sent, the file would be logged in between, and
padding counted on it afterwards would go unnoticed.

| Port | Flow | Deliveries of the re-read reply |
| --- | --- | --- |
| 44000 | f-whole (control) | complete in the first delivery |
| 44001 | f | all data + 1 pad byte \| last 2 pad bytes |
| 44002 | f-pad0 | all data, ending on the last data byte \| 3 pad bytes |

## Expected (fixed) behavior

- WRITE flows: the `REAL-<port>` and `LAST-<port>` LOOKUPs are logged as nfs
  events and alert (`sid:9194101`). No `FAKE-<port>` LOOKUP is ever logged or
  alerted on. The file is CLOSED by the COMMIT with exactly its data (600 or
  601 bytes, sha256 pinned).
- READ flows: the `READMARKER` and `LASTMARKER` replies alert
  (`sid:9194102`, `sid:9194103`), each of the three READs has its own CLOSED
  file with exactly its data, and the LOOKUP alerts. `FAKEMARKER` never
  alerts (`sid:9194104`) and no file holds its data.
- Duplicate reply flows: the duplicate reply is ignored, like in the control
  where the reply is cut inside the data: no `DUPMARKER` alert
  (`sid:9194105`), a single CLOSED file of 501 bytes, and the LOOKUP alerts.
- Closed file flows: exactly two CLOSED files, the first READ's file with
  exactly its 601 bytes (size and sha256 pinned, the re-read reply's padding
  is never counted) and the `READMARKER` file of the third READ, which alerts
  (`sid:9194102`). The re-read reply logs no file of its own. The LOOKUP
  alerts.
- No anomaly and `app_layer.error.nfs_tcp.parser` is 0.

nfs events can be logged on a packet of either direction, so they are matched
by the unique per-flow LOOKUP name rather than by port. Raw TCP rules
(`sid:9194106` to `sid:9194108`) confirm that the tails and the duplicate
reply are on the wire.

The control flows pass on the vulnerable build, which confirms the expected
values. The w-whole and r-whole flows deliver the records of a and d
complete: the complete-record path already skips the record tail, and the
partial path must do the same. Likewise, f-whole delivers the re-read reply
complete: the complete-record path already consumes it without counting any
of it as data of the closed file.

## Vulnerable behavior

On `main` @ 4badfd13f4 and `main-8.0.x` @ 08005f03ba, all controls pass and:

- a, b, split, a-pad3: the `FAKE-<port>` LOOKUP is logged and alerts.
- c: `malformed_data` and a parser error. REAL, LAST and the COMMIT are not
  parsed, and the file is TRUNCATED.
- d, d-own, d-pad3: the fake reply is stored as the second READ's file and
  alerts on `FAKEMARKER`. The real `READMARKER` reply is ignored.
- e, e-pad0: the padding that arrives after the data is parsed as the start of
  an RPC record, which is a parser error, and the LOOKUP is lost.
- f, f-pad0: the same parser error on the padding after the re-read data. The
  `READMARKER` reply and the LOOKUP are lost.

The flows also cover three partial fixes. A continuation that keeps the chunk
until its record tail is consumed, but only takes the tail from deliveries
after the one that completes the file data, passes b, split and d-own, but
fails a, c, a-pad3, d and d-pad3. The tail is parsed as RPC records (or is a
parser error), and then the same number of bytes is consumed from the next
delivery, which loses the REAL LOOKUP or the `READMARKER` reply. A partial
READ reply that holds all of its data but keeps its request in the request
map fails e and e-pad0: the `DUPMARKER` reply alerts and is logged as a
second file. A continuation that passes the padding after the data to the
file tracker of the handle even when its file is already closed fails f and
f-pad0: the first READ's file is logged with the padding counted in its size
(603 and 604 bytes instead of 601; its sha256 is unchanged).

## Regenerate the PCAP

```
./make-pcap.py
```

It uses Scapy and writes `input.pcap` in this directory. The output is
deterministic (fixed MACs, sequence numbers, xids and timestamps). It also
prints the per-flow table with the sha256 values pinned in `test.yaml`.
