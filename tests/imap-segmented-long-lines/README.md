Long command and response lines arriving in many segments are only parsed in
full once their line feed arrives, so a client line made of 40,000 empty lists
does not cost the whole buffered line per list on every segment. The same
applies to the rest of a command line after a literal and to a long untagged
response. Each line is truncated to 8 KiB, and parsing continues with the next
command. The client lines raise `imap.line_too_long`; the server line raises no
event and is logged with `reply_truncated`.
