# Test Purpose

Response-direction counterpart to `bug-8884-08`.

Test that a reply sharing a stream slice with the remainder of an oversized
reply is still parsed, and reaches the transaction waiting for it.

With `USER` and `PWD` outstanding, the server sends `550 ` and 40 `A`s -- over
the 32 byte limit set via `args` -- with no LF in that segment, then `AAAA\r\n`
followed by `226 done\r\n` in the next. The `AAAA` finishes the oversized `550`
reply, which is reported truncated on the `USER` transaction; the `226` behind
its LF must reach the pending `PWD` transaction, leaving the later `221` with
`QUIT`.

`bug-8884-07` covers the same split with nothing behind the remainder's LF.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
