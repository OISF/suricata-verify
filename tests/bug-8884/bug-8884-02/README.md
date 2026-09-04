# Test Purpose

Response-direction counterpart to `bug-8884-01`.

Test that a reply sharing a stream slice with an oversized reply is still parsed
when the oversized reply carries its own LF.

With `USER` and `PWD` outstanding, the server sends `550 ` and 28 `B`s plus CRLF
-- 34 bytes with the delimiter, over the 32 byte limit set via `args` --
immediately followed by `226 done\r\n` in the same segment. The `550` is
reported truncated on the `USER` transaction and the `226` must reach the
pending `PWD` transaction.

Companion to `ftp-too-long-response-mid-slice`, which covers the oversized reply
that arrives without its LF; see `bug-8884-01` for the
defect this shape exercises.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
