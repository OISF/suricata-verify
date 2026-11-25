## Purpose

`DATA` only applies the line buffer limit while the MIME parser is still in header state; body lines
are handed over in fragments of any length. A chunked message must behave the same, or an attachment
sitting on one long line silently loses everything past the first 4 KiB and is still reported
`CLOSED`. The same message goes out over `BDAT <n> LAST` (port 40014) and over `DATA` (port 40015),
so a divergence shows up as two different sizes for one payload.

## Notable contents

A base64 attachment on a single 8192-character line (6144 bytes decoded), an 8bit attachment that is
one 12288-byte line, and a 5000-byte `X-Long` header line that must still be capped - once per flow.
