A `BDAT` chunked message carrying a base64 attachment, with the chunk boundary
falling inside the base64 line, plus the same message over `DATA` as the control.
The chunked body has to reach MIME decoding and file extraction: decoded
`file_data` detection, the attachment in the email fields and a closed file.
