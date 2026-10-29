Test that a transactional (`=>`) HTTP rule whose toserver buffer has the
higher progress value does not alert on its toserver half alone.

The exchange is a single `GET /index.html` with `Host: example.com`,
answered by `HTTP/1.1 200 OK`. Both rules require `http.stat_msg`
content that is never present ("ZZZZZZ"), so neither can match.

- sid 1 uses `http.host` (toserver, progress 2) next to `http.stat_msg`
  (toclient, progress 1): the engine list ends with a toserver engine, so
  the toserver pass used to fall off the end of the list and declare a
  full match while the toclient half was still un-inspected. This is the
  reproducer for Redmine #9087: it alerted before the fix.
- sid 2 is the control using `http.uri` (toserver, progress 1) so the
  list ends with the toclient engine: that ordering already behaved
  correctly.

Run `python3 gen_input_pcap.py` to regenerate `input.pcap`.
