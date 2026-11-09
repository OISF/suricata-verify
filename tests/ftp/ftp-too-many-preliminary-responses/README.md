# Test Description

A `1xx` preliminary response leaves the FTP transaction open, so a server that
keeps sending them adds every line to the same transaction. Suricata keeps at
most 16 preliminary responses per transaction and raises
`ftp.too_many_preliminary_responses` the first time it drops one. Multi-line
replies are not limited.

## PCAP

Handcrafted: one FTP session. The server answers `USER` with 100 `150 \r\n`
lines and then `331`, followed by `PASS`/`230`, a 42-line reply to `FEAT`,
and `QUIT`/`221`.

## Related issues

Ticket https://redmine.openinfosecfoundation.org/issues/9211
