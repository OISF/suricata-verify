## Purpose

The message is ended by an empty `BDAT 0 LAST`, which RFC 3030 section 2 allows for a sender that
does not know the size of the last piece. The body has no closing MIME boundary, so the attachment
is only closed when the message ends - it needs a fileinfo record.

## Notable contents

`BDAT <n>` with the message, then `BDAT 0 LAST`.
