## Purpose

A `BDAT` command that is both malformed and declares an impossible chunk length: `BDAT 2000000000x`.
The declaration parses, the octet count it names is over `max-bdat-chunk-len`, and the command line
does not end there. The command is a syntax error, the server rejects it, and no chunk follows it - so
there is nothing to skip and the anomaly to report is `INVALID_BDAT`, not the length of a chunk that
will never be sent.

This is worth pinning because the skip decision is latched on the transaction: a transaction left
marked as carrying an uninspected chunk hides the *next* message on it as well, and that next message
is not a new transaction here - the refused command does not complete the old one.

## Notable contents

One flow, port 43011, `max-bdat-chunk-len` set to 1000. The refused `BDAT 2000000000x` and the
correct `BDAT <n> LAST` that follows it are both sent on the same transaction, whose envelope is
`MAIL FROM:<alice@example.com>` / `RCPT TO:<bob@example.com>`.
