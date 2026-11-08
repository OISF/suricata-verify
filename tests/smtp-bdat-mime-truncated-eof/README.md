## Purpose

The chunk stops half way through the attachment and the stream ends. The file must be reported
TRUNCATED, not CLOSED: the same cut delivered over `DATA` truncates the stored file.

## Notable contents

`BDAT <n> LAST` with only half the octets sent, no `QUIT`, FIN from the client.
