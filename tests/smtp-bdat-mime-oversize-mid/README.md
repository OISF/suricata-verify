## Purpose

The octets behind a chunk declaration above `max-bdat-chunk-len` are counted and skipped: the MIME
parser must not see them. The next declaration is back within the limit, and clearing the skip there
made the parser feed on the rest of the message as if nothing was missing - the attachment closed
`CLOSED` with a hole of 4200 bytes in it, and the line the first chunk ended on was glued to the
first line of the third. The skipped octets are part of the message either way, so the file has to
be reported `TRUNCATED`.

## Notable contents

`max-bdat-chunk-len` set to 1000, and one message in three chunks: 800 octets (headers plus the
start of a base64 attachment), 4200 octets over the limit and skipped, 842 octets `LAST` within the
limit. All three are accepted by the server. One flow, port 42003.
