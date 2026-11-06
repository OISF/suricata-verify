## Purpose

A `BDAT` the server refuses with a 552 after its chunk arrived does end the transaction, but not the
message behind it: the attachment the chunk had opened was never finished, so it got no `fileinfo`
record at all. The refusal has to close the message the way any other end of it does, and the open
file with it - as truncated, since the rest of the chunked body never arrives.

## Notable contents

`BDAT 800` with its octets (the headers and the start of a base64 attachment), then `552 5.3.4`, then
`QUIT`. One flow, port 42001.
