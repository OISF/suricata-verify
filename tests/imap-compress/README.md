After a tagged OK to `COMPRESS DEFLATE` (RFC 4978) both directions are a
deflate stream, which is not parsed: the flow is no longer tracked, so its
octets are not read as IMAP lines. The COMPRESS command itself is still
logged and inspected. A rejected COMPRESS leaves parsing as it was.

A client cannot stop the parser with a COMPRESS line the server never read as
a command: one sent while the server reads the data of the previous command (a
SASL response or a literal) is not trusted, as its OK may answer another
command using the same tag.
