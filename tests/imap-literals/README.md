This test verifies that a rejected synchronizing APPEND does not leave literal
state that consumes continuation data belonging to a later IDLE command. It
also includes a successful synchronizing APPEND as a control.

The rest of a command line after a literal was parsed but discarded, so an
argument such as a further SEARCH key never reached the `imap.request` buffer
or EVE.

Literal8 octets (`~{N}`, RFC 3516) are consumed like other literals, both
as an argument and as the last item of a list.

A continuation request that no literal, AUTHENTICATE, IDLE or unknown command
waits for does not take the client's next command as a continuation line.
The continuation lines of an unknown command, also after its literal, are
inspected by `imap.request`, not only logged.

Bytes that are not valid UTF-8 are logged escaped (`\xe9`) rather than replaced
by U+FFFD.

A literal the client is already sending is counted down to its end even when
the server answers the command early, so the rest of its text is not taken as
commands.

A non-synchronizing literal is only skipped when the server may accept it:
after a capability list without LITERAL+ or LITERAL-, the server rejects the
line announcing it and the lines that follow are parsed as commands. Without a
capability list the literal is trusted until the command is answered with BAD.

The data of a LOGIN literal whose continuation request was not seen may be
parsed as a command line: such lines are logged as `<redacted>` until a known
command is parsed.

A continuation request arriving while the literal of an already answered
command is still counted belongs to no command.
