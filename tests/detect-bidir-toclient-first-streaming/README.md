Test that a transactional (`=>`) HTTP rule still alerts when the **toclient
half matches first while the response is still streaming**: the server sends
an early `200 OK` whose chunked body has not terminated when the request
half matches (Redmine #9087). The pair is closed by the toserver pass of
packet 8, against the response that is still open.

While the pair is open, the wrong-variant toclient engines of the rule
(`http2` on this `http1` flow) sit in the "handle bidir engine" skip branch
on every toserver pass. They can never inspect this flow, so they must not
hold the pair open; before the fix they set `other_dir_pending`
unconditionally, the pair could never close, and the rule never alerted.

The test runs in IPS mode (`--simulate-ips`) so every packet is parsed and
inspected as it arrives:

- packet 4: `POST /upload` with `Host: example.com` and
  `Content-Length: 26`
- packet 5: body segment 1 `the-first-`
- packet 6: `HTTP/1.1 200 OK`, `Transfer-Encoding: chunked`, first chunk;
  the toclient half matches here, the response is still streaming
- packet 7: second chunk, the response is still streaming
- packet 8: body segment 2 `part-secret-`; the toserver half matches here
  and closes the pair
- packet 9: body segment 3 `tail`; the request completes
- packet 10: terminating chunk; the response completes

Rules:

- sids 21 and 22 are the standard halves over the same two buffers: they
  prove the response side matches at packet 6 and the request side at
  packet 8, independently of the pair requirement.
- sid 1 is the pair whose halves both genuinely match this pcap
  (`http.request_body` carries `secret`, `http.stat_code` is `200`). It
  alerts once on packet 8, where the toserver pass closes the pair.
  `test.yaml` asserts `count: 1, pcap_cnt: 8`.

Alert counts per sid, measured in IPS mode on built binaries:

| build | sid 1 | sid 21 | sid 22 |
|---|---|---|---|
| `2e82e8472` (wrong-variant pending) | 0 | 1@6 | 1@8 |
| this head | 1@8 | 1@6 | 1@8 |

sid 1 is the false negative: it is silent on `2e82e8472` because the
wrong-variant engines hold the pair open, and alerts once on packet 8 with
the fix.

In IDS mode libhtp puts the early response in its own transaction, so the
response never belongs to the request's transaction and the pair cannot
close on any build; the engine's silence there is correct, which is why
this test pins IPS mode.

See `tests/detect-bidir-response-first` for the same ordering where the
early response is complete before the request half matches.
