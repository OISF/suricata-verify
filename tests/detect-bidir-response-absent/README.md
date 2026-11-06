Test that a transactional (`=>`) rule does not alert when its other
direction can never match this transaction: the server answers the request
without any HTTP response (bare ACK, then FIN), so no response tx is ever
parsed and the toclient engines never run (Redmine #9087).

This is the shape Lukas Sismis called out as the correctness risk of
requiring both halves: if the "other direction pending" state can be set by
an engine that has no chance of running for this tx, the rule must not be
allowed to alert from the toserver half alone.

- packet 4: `POST /upload` with `Host: example.com`, `Content-Length: 14`
  and the body `xxxxsecretxxxx`
- packet 5: server ACK
- packet 6: server FIN, no application data
- packets 7-8: client FIN and ACK

Rules:

- sids 1, 2 and 11 must never alert; sid 2 is the variant whose toclient
  condition is `http.stat_code`, i.e. a buffer the response parser would
  have provided had there been a response.
- sid 21 is the positive control: the same request buffer, plain
  `flow:established,to_server`, alerts once.
- The `http` event has no `http.status`, which pins that no response tx
  exists for the checks above to be meaningful.
