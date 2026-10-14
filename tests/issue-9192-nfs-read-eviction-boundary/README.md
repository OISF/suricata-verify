# Redmine #9192 NFS READ continuation consumed to the record boundary after eviction

Regression test for https://redmine.openinfosecfoundation.org/issues/9192.

When the request map entry and the file transaction of a partially
received READ reply are gone, the parser still knows where the reply
record ends. The rest of the record must be consumed exactly up to that
boundary: not less, and not the whole delivered buffer. This test puts the
next RPC record in the same segment as the end of the evicted record, so
any other amount loses the next record.

The same applies when a new READ call for the same file handle has created
a new file transaction in the meantime. That transaction belongs to the new
READ, not to the continuation of the old reply.

Each flow is one NFSv3 TCP connection:

1. READ call (xid 0x91921001) for file A, offset 0.
2. The first 200 bytes of its reply record: RPC and READ headers and 152
   bytes of file data. The record is at least 512 bytes, so it takes the
   partial READ path.
3. NULL calls that are never answered: 1 on the control flows, 600 on the
   eviction flows.
4. A second READ call (xid 0x91922002), offset 0, for file B, or for file A
   again on 41025 and 41026.
5. One segment with the rest of the file A reply record followed by the
   complete reply to the second READ (eof=1). Its file data is 32 bytes:
   `R9192-NEXT-RECORD-MARKER-DATA-OK` on 41021 to 41024 and
   `R9192-REPLACEMENT-READ-MARKER-OK` on 41025 to 41027. The file A
   continuation starts with `00 00 00 10`, an undecodable RPC record marker
   (fragment length 16), if it is ever parsed as a new record.
6. LOOKUP call and reply.

| Client port | File A data (XDR pad) | NULL calls | Second READ | Rest of record A in segment 5 |
| --- | --- | --- | --- | --- |
| 41021 | 512 (0) | 1 (control) | file B | 360 data bytes |
| 41022 | 512 (0) | 600 (eviction) | file B | 360 data bytes |
| 41023 | 513 (3) | 1 (control) | file B | 361 data bytes, 3 pad bytes |
| 41024 | 513 (3) | 600 (eviction) | file B | 361 data bytes, 3 pad bytes |
| 41025 | 512 (0) | 1 (control) | file A | 360 data bytes |
| 41026 | 512 (0) | 600 (eviction, replacement) | file A | 360 data bytes |
| 41027 | 512 (0) | 600 (eviction) | file B | 360 data bytes |

`test.yaml` sets `app-layer.protocols.nfs.max-tx=64` and keeps the default
`max-requests` of 512. On the eviction flows the 600 calls push the READ
xid out of the request map, and they force-close the file A transaction
(tx_id 0, `too_many_transactions`) while its continuation is pending. Any
`max-tx` up to 599 force-closes it during the NULL calls, before the second
READ call. 41026 needs that: with a `max-tx` of 600, its second READ call
still finds the file A transaction open and creates no new one. Any
`max-requests` up to 601 evicts the xid.

On 41026 the second READ call is for file A, whose transaction is closed
by then, so the call creates a new file A transaction (tx_id 601) before
the continuation of the first reply arrives. 41027 is the same flow with
the second READ for file B, so no transaction replaces the closed one. On
the control flow 41025 the first file A transaction is still open when the
second READ call arrives, so the call creates no transaction: the
continuation completes file A, and the second reply is extracted as a new
file.

Expected behavior with the fix, all flows:

- The reply to the second READ is parsed: its `file.data` marker rule
  (sid 9192101 on 41021 to 41024, sid 9192105 on 41025 to 41027) and the
  LOOKUP rule (sid 9192102) alert, and its file is CLOSED with 32 bytes and
  its sha256.
- There is no `malformed_data` anomaly, no exception policy on the flow,
  and `app_layer.error.nfs_tcp.parser` is 0.

Control flows: file A is CLOSED with all of its data (512 or 513 bytes)
and its sha256, and its continuation bytes alert in `file.data`
(sid 9192104).

Eviction flows: file A is TRUNCATED. The observed size is 152 bytes, the
data of the first segment, and the test asserts it. The continuation is
consumed to the record boundary without being added to any file, so sid
9192104 does not alert. On 41026 the continuation leaves the new file A
transaction alone, and the second READ's file is extracted with it: the
test asserts its fileinfo `tx_id` of 601.

The 513 byte flows check that the XDR pad is part of what is consumed.
Stopping at the last data byte would leave the pad in front of the file B
reply. Consuming the pad twice would cut into that reply. A fallback that
consumes the whole delivered segment would drop the second reply on all
eviction flows.

Without the fix, the continuation on the eviction flows is parsed as an RPC
record header. Before the fix, the READ file handle was only found through
the evicted request map entry. With the handle tracking but without the
fallback for a missing file transaction, nothing of the continuation is
consumed. Either way, the undecodable marker is a fatal parser error and
NFS parsing stops for the flow: the second READ's file is never extracted,
there is no marker or LOOKUP alert, and `malformed_data` and a parser error
are raised. The raw TCP marker rules (sid 9192103 and 9192106) still
match. The control flows pass on all builds.

With the fallback, but giving the continuation to any open file A
transaction, only 41026 fails: the continuation goes to the new file A
transaction, whose file is not open yet. Nothing of it is consumed, the
same fatal parser error follows, and the new transaction is closed without
a file. 41027 passes with such a fix.

The PCAP is synthetic. Regenerate it with `./make-pcap.py`, which uses
Scapy and writes `input.pcap` deterministically. The flows 41025 to 41027
are appended after the first four, which are unchanged.
