# Test Description

Checks that `app-layer.protocols.ftp.max-preliminary-responses` sets how many
preliminary (`1xx`) responses a transaction keeps. With the limit set to 4, the
`USER` transaction keeps 4 of the 100 `150` responses and the final `331`.

## PCAP

Reuses the pcap of `ftp-too-many-preliminary-responses`.

## Related issues

Ticket https://redmine.openinfosecfoundation.org/issues/9211
