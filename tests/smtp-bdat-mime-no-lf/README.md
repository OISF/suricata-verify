## Purpose

A message body that is one 64 KiB run without an LF. The chunked path has to keep handing it to the
MIME parser in pieces without treating it as one enormous line: `DATA` does not cap body lines, only
header lines, so a cap here would drop everything past the first piece and still call the message
done. The piece-by-piece handover also reuses one carry buffer, so this is run under LSan.

## Notable contents

Headers, then `A` * 65536 with no LF anywhere in it, as a single `BDAT <n> LAST`.
