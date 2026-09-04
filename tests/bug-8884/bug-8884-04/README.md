# Test Purpose

Test that a *transfer* command hidden behind an oversized command still reaches
the FTP data-channel negotiation.

`bug-8884-01` shows that a plain command (`QUIT`) behind an oversized line is
parsed again after the fix. This case covers the security-relevant half: a
`RETR`/`STOR` hidden the same way drives the data channel. When such a command
is parsed, `FTPParseRequest` runs the transfer-command block that calls
`AppLayerExpectationCreate`, registering the incoming data connection as
`ftp-data` so file extraction engages. If the command is dropped, no expectation
is registered and the transfer moves without Suricata associating it with the
control channel.

The client sends `USER ` and 30 `A`s plus CRLF -- 34 bytes with the delimiter,
over the 32 byte limit set via `args` -- immediately followed by
`RETR secret.txt\r\n` in the same segment. The oversized `USER` is reported
truncated with `request_command_too_long`; the `RETR` behind it must still be
parsed and reach the transfer-command handling. No PORT was negotiated, so that
handling raises `file_before_port` -- the event fires from the exact block that
registers the `ftp-data` expectation, so its presence proves the hidden `RETR`
reached the data-channel negotiation rather than being consumed unparsed.

Before the fix the request loop stopped as soon as a line reached
`max-line-length`, so the `RETR` was consumed without ever being parsed: no
`RETR` transaction, no `file_before_port`, and -- had a PORT been negotiated --
no `ftp-data` expectation, hiding the transfer from file extraction.

An `ftp-data` event on the data connection itself is exercised by real-capture
tests such as `output-eve-ftp-data`; the flowsynth-generated flows here cannot
drive expectation matching on a synthetic data connection, so this test asserts
the control-channel side of the same code path.

## PCAP

PCAP generated with flowsynth; run `make` to regenerate.
