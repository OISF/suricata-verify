Test that a transactional (`=>`) HTTP rule whose **toclient half completes
first** still alerts: the server sends an early `200 OK` while the chunked
request body is still streaming, so the response side is inspected and
reaches its end of buffer before the request side ever matches (Redmine
#9087). Once the toclient side of the transaction is complete and
inspected there is no toclient pass left to close the pair, so the
toserver pass inspects the toclient half itself, against the completed
response, and closes the pair: the rule alerts exactly once.

The test runs in IPS mode (`--simulate-ips`) so every packet is parsed and
inspected as it arrives:

- packet 4: `POST /upload` with `Host: example.com` and
  `Transfer-Encoding: chunked`
- packet 5: `HTTP/1.1 200 OK`, an early answer; the toclient side of the
  transaction is complete and inspected here
- packet 6: the chunk `secret`; the toserver inspection that matches the
  request half and closes the pair
- packet 7: terminating chunk; the request is complete, no new body data

Rules:

- sids 1 and 2 are the guards: the request half matches and the response
  half cannot, so they must stay silent. They alert once each on
  `791605c2a`, which is the reported false positive, and are silent with
  the fix.
- sids 21 and 22 are a plain `flow:established` flowbit pair over the same
  two buffers, proving both halves do match at the packets named above.
- sid 3 is the pair whose halves both genuinely match this pcap
  (`http.request_body` carries `secret`, `http.stat_msg` is `OK`). It
  alerts once on `791605c2a` *because of the bug* - on that build the
  toserver half alone is enough - and it never alerts on `b2a0e561e`,
  because the pair requirement there has no response-first close: the
  toclient side is final before the request half matches, and the toclient
  pass that would close the pair has already run. With the response-first
  close it alerts exactly once on packet 6, where the toserver pass
  inspects the toclient half against the completed response. `test.yaml`
  asserts `count: 1, pcap_cnt: 6`.

Alert counts per sid, measured in IPS mode on built binaries:

| build | sid 1 | sid 2 | sid 3 | sid 22 |
|---|---|---|---|---|
| main `791605c2a` | 1@6 | 1@6 | 1@6 | 1@6 |
| `b2a0e561e` (no response-first close) | 0 | 0 | 0 | 1@6 |
| this head | 0 | 0 | 1@6 | 1@6 |

sid 1 and sid 2 are the checks that matter for the false positive: they
are red on main (1 alert each) and green with the fix. sid 3 is the
response-first pair: it alerts once on main by accident, is silent without
the response-first close, and alerts once on packet 6 with it.

In IDS mode libhtp puts the early response in its own transaction (url
`/libhtp::request_uri_not_seen`), so the response never belongs to the
request's transaction and the pair cannot close on any build; the engine's
silence there is correct, which is why this test pins IPS mode.

See `tests/detect-bidir-http2` for the same rule shape on HTTP/2 in the
ordinary request-first ordering.
