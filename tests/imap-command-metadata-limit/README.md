With unlimited TCP reassembly, oversized unknown keywords, 100,000 empty
arguments, and a large LOGIN argument must be bounded without losing later
commands. A literal marker beyond the retained argument count still controls
literal consumption; the following suffix remains inspectable and logged.
LOGIN credentials stay redacted.

An 8 KiB tag is accepted and matched exactly. Longer tags, including incomplete
fragmented prefixes, produce `imap.line_too_long` and stop parsing. Both client
and server cases start after a completed greeting, checking that the event is
reported even without an existing transaction.
