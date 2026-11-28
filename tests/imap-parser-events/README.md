Test that:
- IMAP event 'line-too-long' is set when a request/response line is longer than its limit
- invalid lines are skipped up to their line end, in both directions, as a
  server answers them with BAD: `imap.invalid_data` is raised once per run of
  them and the following commands and responses are still parsed
- raw stream content of a command is inspected as soon as it is parsed
- the PDU frame of a line following a skipped invalid line starts at that line
- a malformed continuation line (bare CR) is skipped like any invalid line once
  its LF arrives, rather than dropping the data buffered so far
- the transactions carrying those events produce no empty imap records
- an invalid line is not taken as continuation data of an AUTHENTICATE or IDLE
  once the client has sent a later command, even if its tagged reply was not seen
