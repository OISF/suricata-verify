With unlimited TCP reassembly, oversized unknown keywords, 100,000 empty
arguments, and a large LOGIN argument must be bounded without losing later
commands. A literal marker beyond the retained argument count still controls
literal consumption; the following suffix remains inspectable and logged.
LOGIN credentials stay redacted.

An 8 KiB tag is accepted and matched exactly. Longer tags, including incomplete
fragmented prefixes, are kept truncated to 8 KiB, and parsing continues. A
client line raises `imap.line_too_long`; a server line raises no event and is
logged with `reply_truncated`. Both cases start after a completed greeting,
checking that they are reported even without an existing transaction.
