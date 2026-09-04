# NFSv3 WRITE: follow-up on a rejected oversized transaction

WRITE 1 claims 8192 bytes with max-write-size 4096 and is rejected with
write_request_too_large. The rejected file transaction must be closed,
so the follow-up WRITE 2 on the same file handle starts a new
transaction instead of reusing the rejected one.

Checks: write_request_too_large on the first transaction, both WRITE
transactions logged (xid 1 and xid 2), no malformed data, and the
follow-up 100-byte file stored intact.
