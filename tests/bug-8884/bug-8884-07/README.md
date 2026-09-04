# Test Purpose

Response-direction counterpart to `bug-8884-06`.

Test that a rejected reply followed by an unterminated oversized reply does not
leave a stale completion flag that defeats the truncation carry, letting the
oversized reply's tail be parsed as a fabricated reply in the next slice.

With `USER` outstanding, the server sends a run of spaces (rejected by the
response-line parser, but the line getter still records it as complete) followed
by `550 ` and 40 `A`s with no LF -- over the 32 byte limit set via `args` -- in
one segment, and `226 done\r\n` in the next. The `226 done` is the tail of the
oversized `550` reply: it must not become a reply of its own, and the later
`221` must stay with `QUIT` rather than being pulled forward onto it.

The oversized reply's own truncated reporting on this no-LF path is subject to
the separate slice-start window mis-report (Redmine 8859), which is out of scope
here; this test asserts only that the following reply is not fabricated.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
