# Test Purpose

Test that a command sharing a stream slice with an oversized command is still
parsed when the oversized command carries its own LF.

The oversized line is clipped to `max-line-length` for reporting and flagged
truncated, but its LF ends it: everything behind that LF is a separate line and
must go through the parser.

The client sends `PORT ` and 27 `A`s plus CRLF -- 34 bytes with the delimiter,
over the 32 byte limit set via `args` -- immediately followed by `QUIT\r\n` in
the same segment. The `PORT` command is reported truncated and the `QUIT` must
still produce a transaction.

Companion to `ftp-too-long-command-mid-slice`, which covers the oversized
command that arrives without its LF. Before the fix the request loop stopped as
soon as a line reached `max-line-length`, so the rest of the slice -- here the
`QUIT` -- was consumed without ever being parsed, hiding it from inspection and
logging.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
