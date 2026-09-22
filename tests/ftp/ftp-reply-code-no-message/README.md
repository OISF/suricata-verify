# Test Description

A server may answer with a completion code and no message at all, e.g. `221 \r\n`
in reply to `QUIT`.

## PCAP

Handcrafted: minimal FTP session (`USER`/`PASS`/`QUIT`) whose `QUIT` reply is
`221 \r\n`. The other replies carry a message so the regular path stays covered.

## Related issues

Ticket https://redmine.openinfosecfoundation.org/issues/8966
