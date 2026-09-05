# Test Purpose

Verify that IMAP protocol detection does not claim HTTP or FTP traffic that
resembles an IMAP command.

HTTP detection is disabled to isolate IMAP's configured-port probe. FTP is
left in detection-only mode so its `USER` pattern competes with IMAP's global
protocol-detection patterns without enabling the FTP parser. A valid
client-first IMAP CAPABILITY command is included as a positive control.

