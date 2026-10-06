# Test Purpose

Redmine 8859, response direction. Same defect as bug-8859-01, reached through
`FTPParseResponse` instead of `FTPParseRequest`.

The server sends `331 ok\r\n` followed by `550 ` and 28 `B`s -- 32 bytes with no
LF -- in a single segment. `max-line-length` is set to 32 via `args`, so the
second reply line is truncated.

Before the fix the truncated window started at the beginning of the slice, so
the already-consumed `331 ok` line was reported a second time and the real 550
reply was dropped.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
