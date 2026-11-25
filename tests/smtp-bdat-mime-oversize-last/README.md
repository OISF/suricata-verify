## Purpose

A `BDAT <n> LAST` whose length is above `max-bdat-chunk-len` delivers nothing to the MIME decoder,
yet the message it ends was reported complete: the file the earlier chunk opened closed without
`FILE_TRUNCATED`, because the end of the message did not look at the skipped declaration. The last
chunk of a message that was never decoded is missing from the file all the same.

## Notable contents

`max-bdat-chunk-len` set to 1000, `BDAT 800` with its octets (headers plus the start of a base64
attachment), then `BDAT 5042 LAST` over the limit. One flow, port 42004.
