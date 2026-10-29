# Test Purpose

Test that an oversized reply on a response path that jumps straight to
`tx_complete` still settles its truncation state, so the reply behind it is not
discarded.

`bug-8884-03` covers a reply the response-line parser rejects. This covers the
other way the settle can be skipped: the per-command switch in
`FTPParseResponse` handles `EPRT`/`PORT` and jumps to `tx_complete` on invalid
input, past the point where truncation is cleared. If the clear sits after the
switch, an oversized reply on that path leaves the connection-level flag set,
and the next reply -- even in a later stream slice -- is dropped by the line
getter as this line's remainder.

The client sends an invalid `PORT bad`, so the server's reply to it takes the
`PORT` case and jumps to `tx_complete`. That reply is an oversized `500` (`500 `
plus 30 `Z`s, over the 32 byte limit set via `args`). It logs no reply of its
own, but a `USER` then follows and the server's `331` reply -- in the next
segment -- must reach the `USER` transaction. Without the fix the `331` is
discarded and the later `221` is misattributed to `USER`.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
