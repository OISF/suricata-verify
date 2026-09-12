# Well-formed partial WRITE split inside the XDR fill

RFC 2203 requires XDR fragments to be 4-byte aligned, so a well-formed
v3 WRITE record's claim INCLUDES the XDR fill of the file data. Here
the TCP split lands inside the 3-byte fill (all 2149 data bytes plus
1 fill byte ride in the first packet): the fill accounting must absorb
the buffered fill byte so the file content stays exact and the framing
clean. The following WRITE's file is still logged. No malformed data.
