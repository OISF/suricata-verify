## Purpose

A `BDAT <n> LAST` chunk delivered in 100-byte segments, so every segment edge lands in the middle
of a MIME line. The line carry must survive the edges and the buffer must not be re-allocated for
each one (run under LSan).

## Notable contents

The 4 KiB attachment is base64-wrapped at 76 characters; the message is one chunk.
