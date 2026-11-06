## Purpose

A chunk delivered in full but never ended with `BDAT ... LAST`, and the client sends `QUIT`
instead. The transaction has to close with its attachment marked TRUNCATED, rather than being left
open to swallow the next message.

## Notable contents

`BDAT <n>` (no LAST) with the octets delivered, then `QUIT`.
