A BDAT chunk that is never delivered in full: the sender declares 200 octets,
sends 40 and closes the connection. The end of the stream makes the missing
octets definite, which is what smtp.bdat_incomplete_chunk reports.
