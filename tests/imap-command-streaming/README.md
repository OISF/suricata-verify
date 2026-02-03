This test verifies that synchronizing APPEND literals and the client lines used
by IDLE and multi-round AUTHENTICATE exchanges remain inspectable after the
initial command packet. It also checks alert direction and timing, continuation
ownership, credential redaction, and parsing of the next normal command.

Also verifies that a FETCH with an unparenthesized
BODY.PEEK[HEADER.FIELDS (...)] section parses without a fatal error.
