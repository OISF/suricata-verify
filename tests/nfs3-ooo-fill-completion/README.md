# Well-formed partial OOO WRITE: fill inside the claim, gap not filled

RFC 2203 requires XDR fragments to be 4-byte aligned, so a well-formed
v3 WRITE record's claim INCLUDES the XDR fill of the file data. An OOO
WRITE (offset 8192, 2049 data, 3 fill, aligned claim) is split across
packets and completes normally (no queue limit crossed). The OOO extent
has an unresolved gap (the in-order write only covered 0..100), so its
data is not stored; the checks pin the framing: the in-order file is
stored intact and the following WRITE (xid 0x44444444, second handle)
still parses and logs its file. No malformed data.
