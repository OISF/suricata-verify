# Test Description

Test that the engine doesn't access out of bounds elements when checking for
the verdict of the last alert in the packet alert queue. And that it logs
the `pass` verdic correctly, for an "PASS + ALERT" rule. (Sid 8002106).

## PCAP

Shared by Jason Ish. (Reused from bug-8021-alert-max-verdict-01).

## Related issues

https://redmine.openinfosecfoundation.org/issues/7630
https://redmine.openinfosecfoundation.org/issues/8021
