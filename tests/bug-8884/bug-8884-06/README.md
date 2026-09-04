# Test Purpose

Test that a stale per-line completion flag does not defeat the cross-slice
truncation carry and fabricate a command.

`FtpLineState` is reused for every line in a slice, and the line getter sets
`lf_found` only on the path that finds an LF. If it is not reset per call, an
unterminated oversized line that follows a complete line in the same slice sees
the prior line's `lf_found` and clears the truncation carry that was just
raised. The oversized line's continuation in the next slice is then parsed as a
fresh command.

The client sends `ZORP` (unrecognized, so it sets `lf_found` and the loop
continues) followed by `USER ` and 40 `A`s with no LF -- over the 32 byte limit
set via `args` -- in one segment, and `QUIT\r\n` in the next. The `QUIT` is the
tail of the oversized `USER` line, not a command: it must not become a
transaction.

Companion to `bug-8884-07`, the response direction.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
