Test that a transactional (`=>`) HTTP rule still alerts exactly once when
both of its halves match, as a guard against over-fixing the bidirectional
"do not match yet" decision (Redmine #9087).

The exchange is a single `GET /index.html` with `Host: example.com`,
answered by `HTTP/1.1 200 OK`, so `http.stat_msg` is "OK" and both rules
can match.

- sid 1 combines `http.host` (toserver, progress 2) with `http.stat_msg`
  (toclient, progress 1): the engine list ends with a toserver engine.
- sid 2 combines `http.uri` (toserver, progress 1) with `http.stat_msg`
  (toclient, progress 1): the engine list ends with a toclient engine.

Both orderings must produce one alert, not zero (the match would be lost)
and not two (the match would be reported twice), logged on packet 8 - the
server FIN/ACK that takes the response to `response_complete`, i.e. the
packet that completes the last half of the rule.

Run `python3 gen_input_pcap.py` to regenerate `input.pcap`.
