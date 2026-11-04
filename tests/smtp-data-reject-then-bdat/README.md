## Purpose

The client sends `DATA` with junk parameters, the server answers `501`, and the client pushes the
message anyway as a `BDAT ... LAST` chunk on the same transaction. The refused `DATA` must not leave
the transaction marked as carrying a DATA message: if it does, the chunked message is never MIME
parsed and never file extracted, so it slips past inspection entirely.

## Notable contents

`MAIL`, `RCPT`, `DATA syntax error` answered `501`, then one `BDAT` LAST chunk holding a base64
attachment. Checks are the fileinfo record for the attachment and a `file_data` content match.
