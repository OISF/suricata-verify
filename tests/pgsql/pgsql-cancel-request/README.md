# Test Description

Showcase Suricata output and behavior when it inspects PostgreSQL traffic where
a `CancelRequest` message is sent.

A CancelRequest message is sent by the FrontEnd (client) when it wants to cancel
a Query. It is sent to a new port, so this creates a new transaction. No direct
message is sent to confirm that the CancelRequest was processed, but if it is,
the transaction/process waiting for the Query will receive an Error Message
indicating that the Query was canceled (cf
https://www.postgresql.org/docs/16/protocol-flow.html#PROTOCOL-FLOW-CANCELING-REQUESTS).

## PCAP

Shared by Jason Ish, sample of a local query to a sample local database.

## Related issues

Task for adding pgsql message: https://redmine.openinfosecfoundation.org/issues/6577
