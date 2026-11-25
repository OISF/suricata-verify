Test that a transactional (`=>`) HTTP rule alerts once, and only on the
response, when its fast_pattern is on the request body and matches while
the body is still in progress (Redmine #9087).

The test runs in IPS mode with the default configuration. Every packet is
parsed and inspected when it arrives, and the request body is inspected
while it is in progress:

- packet 4: `POST /upload` with `Host: example.com` and
  `Transfer-Encoding: chunked`
- packet 5: the chunk `secret`, the body is inspected
- packet 6: the terminating chunk, the request is complete; there is no
  new body data, so `http.request_body` is not inspected again
- packet 7: `HTTP/1.1 200 OK`
- packets 8-10: TCP teardown

Rules:

- sid 1 combines `http.request_body` (the fast_pattern) with
  `http.stat_msg` "OK".
- sid 2 combines `file.data: to_server` (the fast_pattern) with
  `http.stat_code` "200".
- sids 11-12 are sids 1-2 with a response condition that does not match
  (`http.stat_msg` "ZZZZZZ", `http.stat_code` "404").
- sids 21-22 are standard `->` rules on the same request buffers, they
  must alert on packet 5.
- sids 23-24 are the standard flowbits form of sid 1: sid 23 sets a
  flowbit on the request body without alerting, sid 24 alerts on the
  response when it is set.

sids 1, 2 and 24 must alert exactly once, on packet 7, sids 21-22 exactly
once, on packet 5, and sids 11-12 must not alert.

Unlike the request body, `file.data` is inspected again on packet 6: in IPS
mode a file smaller than the minimal inspect size is inspected in full on
every packet. sid 2 therefore finds its match again after the body is
complete.

Run `python3 gen_input_pcap.py` to regenerate `input.pcap`.
