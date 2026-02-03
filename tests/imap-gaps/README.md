Packet loss inside a literal, in either direction, only removes octets of it:
parsing stays in sync and the rest of an email is not taken as commands or
responses. A gap running past the end of a literal resyncs on the next command.
A lost continuation request marks a pending literal ready once the gap is
reported, and a response gap during IDLE keeps the client's DONE.
A client line after AUTHENTICATE or IDLE whose continuation request was lost
is still taken as its continuation, even when the gap is reported after it.
The PDU frame of a literal resumed after a gap ends with the literal.
After a gap ending inside a line, only the rest of that line is skipped: the
commands and replies following it in the same segment are still parsed.
A synchronizing literal whose continuation request is not seen is given up
once the client sends another line: a later request gap is not taken for its
octets and the commands after the gap are still parsed.
After a gap losing the line that announces a literal, the text of the literal
is skipped until a known command instead of becoming unknown commands. The
same goes for responses: the text is skipped until the reply to a pending
command or a known untagged response, without `imap.invalid_data`.
A literal announced by an AUTHENTICATE line is given up once client data is
taken as the SASL response, so a later response gap is not taken for its
continuation request.
