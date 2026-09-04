# Test Purpose

Test that a command sharing a stream slice with the remainder of an oversized
command is still parsed.

An oversized command that arrives without its LF is reported truncated and its
remainder -- everything up to and including the LF in a later slice -- is not a
line of its own, so the parser drops it. Only those bytes belong to it: a
command behind that LF is a line in its own right and must be parsed.

The client sends `USER a\r\n` followed by `PORT ` and 27 `A`s -- 32 bytes, at
the limit set via `args` -- with no LF in that segment, then
`PASS s3cret\r\nQUIT\r\n` in the next. The `PASS s3cret` is the remainder of the
oversized `PORT` line rather than a command, so it must not become a
transaction; the `QUIT` behind its LF must.

`bug-8884-06` covers the same split with nothing behind the remainder's LF.
The oversized line's own reported command and data are subject to the separate
slice-start window mis-report (Redmine 8859), so this test asserts only the
truncation event, not that line's contents.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
