# NFSv3 split record whose claim is below the parsed extent

A v3 WRITE call and a v3 READ reply whose record claims fewer bytes than the
file data their own args promise (4000 promised, 660/600 really in the
record). Delivered whole, the args are parsed against the complete record;
delivered split across a segment boundary, the partial-record path is what
reads them, and trusting the promise runs the file data past the record
boundary into the following RPC records. Each flow ends with a LOOKUP of
`cbe-marker-name` in the bytes right after the boundary: the stream stayed in
sync only if it is parsed, and no file may be stored for the bytes that never
arrived.
