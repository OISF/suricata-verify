# Test Purpose

Redmine 8859. Test that an over-long FTP command that follows a shorter,
complete command in the same stream slice is reported starting at the
unconsumed remainder of the slice, not at the start of the slice.

The client sends `USER a\r\n` followed by `PORT ` and 27 `A`s -- 32 bytes with
no LF -- in a single segment. `max-line-length` is set to 32 via `args`, so the
second line is truncated.

Before the fix the truncated window started at the beginning of the slice, so
the transaction was mis-classified as a second `USER` command carrying
`a\r\nPORT AAAAAAAAAAAAAAAAAAA`, and the last 8 bytes of the real `PORT`
command were dropped.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
