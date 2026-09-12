# Well-formed partial WRITE split at the end of the file data

RFC 2203 requires XDR fragments to be 4-byte aligned, so a well-formed
v3 WRITE record's claim INCLUDES the XDR fill of the file data. Here
the TCP split lands exactly at the end of the 2149 data bytes: the
promise is file-data-based (0) while 3 unbuffered fill bytes remain,
and the record loop would parse them as a record header. The file must
be stored with the exact content and the following WRITE's file still
logged. No malformed data.
