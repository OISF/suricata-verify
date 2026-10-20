# Test Purpose

Test that an over-long command starting part way into a stream slice leaves the
truncation state set, so the remainder of that command is discarded through its
LF instead of being parsed as new commands -- and that the discard stops at that
LF, so a command sharing the slice with it is still parsed.

`ftp-too-long-command-first` drives the same discard path with the over-long
command at the beginning of a slice, but cannot observe it: its remainder is
`Z`, which is not a command, so no transaction is created whether the remainder
is discarded or parsed. This test covers the case where a shorter, complete
command was consumed from the same slice first, and makes the remainder a real
command so the difference shows.

The client sends `USER a\r\n` plus `PORT ` and 27 `A`s -- 32 bytes with no LF --
in one segment, then `PASS s3cret\r\nQUIT\r\n` in a later one. `max-line-length`
is set to 32 via `args`. The `PASS s3cret` is the remainder of the truncated
`PORT` command and must not become a transaction of its own; the `QUIT` behind
it must.

Both defects were raised in review of the Redmine 8859 fix and share its input
shape. The truncation state was cleared by a stale flag left over from the
preceding complete line, which let the remainder be parsed as a command, and the
recovery branch then discarded the whole slice that carried the remainder's LF,
taking any following command with it.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
