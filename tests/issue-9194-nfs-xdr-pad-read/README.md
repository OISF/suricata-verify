# Redmine #9194 NFS READ reply XDR padding split from the file data

Regression test for https://redmine.openinfosecfoundation.org/issues/9194,
to-client (NFSv3 READ reply) direction.

A READ reply record of at least 512 bytes whose first delivery is incomplete
takes the partial-record path. When the file data length is not a multiple
of 4, the record ends with 1 to 3 bytes of XDR padding. If any of the
padding arrives in a later delivery than the last data byte, the vulnerable
parser ends the continuation at the last data byte and parses the remaining
padding as the start of the next RPC record. This is a fatal parser error,
and NFS parsing stops for both directions of the flow.

Each TCP flow sends two pipelined READ calls, the split reply for the first
file, a READ reply carrying a marker for a second file, and then a LOOKUP.
Unless noted, the remaining padding and the marker reply share a segment.
Each data segment is ACKed separately, so it is delivered to the parser on
its own. The first-delivery shapes are:

- a: the first delivery ends on the last data byte.
- b: the first delivery ends 1 or 2 bytes into the padding.
- c: header and 200 data bytes; the rest of the data then ends on the last
  data byte.
- d: like c, but the second delivery ends 1 or 2 bytes into the padding.
- "pad alone": the padding is a segment on its own.
- "split pad": the padding itself is split across segments, so a delivery
  that holds only padding ends inside the padding.

| Data bytes (pad) | Controls | Split flows (client port) |
| --- | --- | --- |
| 515 (1) | 40100, 40110 | a 40101, c 40104, a + pad alone 40107, a + split 600-byte marker reply 40111 |
| 514 (2) | 40200 | a 40201, b 40202, c 40204, d 40205 |
| 513 (3) | 40300, 40309 | a 40301, b 40302 40303, c 40304, d 40305 40306, c + pad alone 40308, a + split pad 1+2 40310, b + split pad 1+1 40311, c + split pad 1+1+1 40312 |
| 415 (1), with attributes | 40400 | a 40401, c 40404 |
| 513 (3), eof=0 | 40500 | c 40504 |

In the controls, the reply is delivered complete. In 40110 it is followed by
the start of the 600-byte marker reply. In 40309 the continuation carries the
data end, the padding and the marker reply together. All the controls already
pass on vulnerable builds.

Expected (fixed) behavior on every flow, matching the controls:

- The marker reply is parsed and the `file.data` rule alerts.
- The LOOKUP alerts on `nfs_procedure:3`.
- The first file is CLOSED with exactly its data length and sha256. Padding
  is not file data. With eof=0 the file stays open and is TRUNCATED at the
  end of the flow.
- There is no NFS anomaly and `app_layer.error.nfs_tcp.parser` is 0.

On vulnerable builds, every split flow raises `malformed_data` and a parser
error, and loses both NFS alerts. The raw TCP marker rule still matches there.

The PCAP is synthetic. Regenerate it with `./make-pcap.py`, which uses Scapy
and writes `input.pcap` deterministically.
