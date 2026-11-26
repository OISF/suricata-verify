# stream-tcp IPS overlap rewrite on retransmits

IPS test for the TCP stream inline overlap handling of retransmits that
overlap stored segment data: `StreamTcpInlineSegmentCompare` /
`StreamTcpInlineSegmentReplacePacket` must rewrite the retransmitted
payload in place from the stored stream data, aligned on `base_seq`.

Flow 1, 10.0.0.1:33333 -> 10.0.0.2:12345: the toserver stream is
`A*16384, K*16383 + Q, E*512`. The stream base stays unslid here.
Packets 9-11 retransmit parts of it with different heads:

- packets 9/10 retransmit [33000, 34024) with C/D data; the overlap
  with the stored segment is rewritten to the stored bytes (K/Q), so
  neither head survives;
- packet 11 retransmits [33768, 34024) with H data; stored stream
  byte 33768 is Q, so a correct rewrite puts Q in front.

Flow 2, 10.0.0.3:44444 -> 10.0.0.4:53 (DNS over TCP): covers a segment
whose head was pruned. The app layer consumes only the first query, so
the stream base slides to the end of that query, into the head of the
stored segment. The retransmit at `base_seq` then overlaps the pruned
head: a correct rewrite starts at the stored byte for `base_seq` (the
DNS length prefix `05 00`), while pre-fix code copies from 25 bytes
further into the stored data (`LM`).

Checks:

- `sid:10` (tcp-stream, first byte 'A') fires twice: reassembly
  sanity for flow 1.
- `sid:11` (tcp-pkt, first byte 'Q') fires exactly once, for the
  rewritten packet 11; a missed or misaligned rewrite leaves its H
  head (0 matches) or rewrites the wrong bytes.
- `sid:12` (tcp-pkt, first byte 'E') fires exactly once, for the
  unrewritten E packet.
- `sid:13` (tcp-pkt, first bytes `05 00`) fires exactly once, for the
  pruned-head retransmit of flow 2.
- `sid:14` (tcp-pkt, first bytes 'LM') does not fire: the shifted copy
  of the pre-fix offset arithmetic.
- the flow event of flow 1 is logged with `alerted: true` (the pcap
  ends with a FIN handshake).

Notes:

- the test runs in IPS mode (test name contains "ips") with fixed
  `stream.reassembly.*-chunk-size: 512` and no chunk-size
  randomization.
- `make-pcap.py` regenerates the pcap with fixed packet timestamps.
