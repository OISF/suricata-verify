Test that a transactional (`=>`) HTTP rule alerts once, and only on the
response side, when its request body arrives after the request headers
(Redmine #9087).

The test runs in IDS mode with the default configuration. In IDS mode data
is parsed once the other side acknowledges it, and a
direction is inspected on its next packet. Every acknowledgement rides on a
packet that is sent anyway:

- packet 4: client, `POST /upload` with `Host: example.com`
- packet 5: server ACK, the headers are parsed
- packet 6: client, the body `xxxxsecretxxxx`; the request side is
  inspected with the headers only
- packet 7: server, `HTTP/1.1 200 OK`; it acknowledges the body, which is
  parsed
- packet 8: client FIN; it acknowledges the response, which is parsed, and
  the request side is inspected with the body
- packet 9: server FIN; the response side is inspected

Rules:

- sids 1-3 combine a header buffer (`http.uri` or `http.host`, the
  fast_pattern) with `http.request_body` or `file.data: to_server` and a
  response condition that matches. The headers match on packet 6, the body
  on packet 8.
- sid 4 is the control with `http.request_body` as the fast_pattern, next
  to `http.host` and a matching response condition, so the rule is first
  inspected with the body on packet 8.
- sids 11-14 are sids 1-4 with a response condition that does not match
  (`http.stat_msg` "ZZZZZZ", `http.stat_code` "404").

sids 1-4 must alert exactly once, on packet 9, and sids 11-14 must not
alert.

Run `python3 gen_input_pcap.py` to regenerate `input.pcap`.
