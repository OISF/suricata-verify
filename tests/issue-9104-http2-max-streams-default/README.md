# HTTP/2 default stream limit

https://redmine.openinfosecfoundation.org/issues/9104

Verify that the default HTTP/2 stream limit permits 256 concurrent streams
and rejects a 257th, raising `too_many_streams` and SID 2290012.
`http2.max-streams` is deliberately left unset.

`input.pcap` contains real HTTP/2 traffic generated and captured in a lab.
The server advertises `SETTINGS_MAX_CONCURRENT_STREAMS` of 512, so both
connections are valid for the endpoints. Suricata must apply its own limit.

- Client port 42000 opens 256 streams with paths `/limit-256/000` through
  `/limit-256/255`. Each receives response headers but no response body or
  END_STREAM. All 256 transactions remain live. The test checks that all
  requests are logged and the 256th request is inspected without an anomaly.
- Client port 42001 repeats this and attempts stream 257, with path
  `/limit-257/256`. Suricata must not log or inspect that request. Crossing
  the limit marks the 256 existing transactions with `too_many_streams`.
  The test checks all 256 anomalies and the shipped SID 2290012 in both
  directions on the last accepted transaction. The per-packet alert queue
  prevents every affected transaction from producing an alert.

Requests and response headers are exchanged individually. The initial
SETTINGS transactions have been processed and released before the stream
boundary is reached. Neither connection sends GOAWAY while its streams are
open, avoiding a separate connection-level transaction at the boundary.
There are no compressed bodies or decompression allocations in this case.

The capture is replayed in single runmode with checksum validation disabled.
