# Test Purpose

Response-direction counterpart to `ftp-too-long-command-mid-slice`.

Test that an over-long reply starting part way into a stream slice leaves the
truncation state set, so the remainder of that reply is discarded through its LF
instead of being parsed as new replies -- and that the discard stops at that LF,
so a reply sharing the slice with it still reaches its transaction.

The server sends `331 ok\r\n` plus `550 ` and 28 `B`s -- 32 bytes with no LF --
in one segment, then `CCCC\r\n226 done\r\n` in a later one. `max-line-length` is
set to 32 via `args`. The `CCCC` is the tail of the truncated `550` reply and is
dropped; the `226 done` behind it must be attached to the pending `PWD`
transaction.

See `ftp-too-long-command-mid-slice` for the defects this shape exercises.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
