# Test Purpose

Test that an oversized reply the response line parser rejects does not swallow
the reply behind it.

`SCFTPParseResponseLine` returns NULL for a line that is empty once trimmed, so
an oversized run of spaces produces no response line. The truncation state must
still be settled for that line, or the next reply in the slice is mistaken for
the tail of it and discarded.

With `USER` and `PWD` outstanding, the server sends 34 spaces and CRLF -- over
the 32 byte limit set via `args` -- immediately followed by `226 done\r\n`. The
`226` must reach the pending `PWD` transaction.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
