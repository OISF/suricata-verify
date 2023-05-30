# Test Description

This test shows that SMTP long lines should be handled per direction.
Currently, we track long lines in one variable per state.
In this test, as EHLO comes after the long line, it is ignored by the
parser and EHLO command is not logged. It has been fixed as a part of
the fix for redmine ticket 6053

## PCAP

Locally generated.

## Related issues

https://redmine.openinfosecfoundation.org/issues/6053
