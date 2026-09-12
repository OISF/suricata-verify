# Well-formed partial in-order WRITE continuation: exact content

RFC 2203 requires XDR fragments to be 4-byte aligned, so a well-formed
v3 WRITE record's claim INCLUDES the XDR fill of the file data. An
in-order WRITE (offset 100, 2149 data, 3 fill, aligned claim) is split
across packets and completes normally: the promise must cover exactly
the unbuffered file data so the continuation lands on the record
boundary. The file is stored with the exact content (100 + 2149 bytes)
and the following WRITE's file is still logged. No malformed data.
