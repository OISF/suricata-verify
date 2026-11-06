## Purpose

The server rejects a `BDAT` before any of its octets arrive, and the client falls back to `DATA` on
the same transaction. The MIME parser allocated for the refused chunk must not still be there when
`DATA` sets up its own: debug-validation builds used to assert, and release builds leaked it.

## Notable contents

`BDAT 100` answered `554`, then `DATA` with the full message and its dot terminator.
