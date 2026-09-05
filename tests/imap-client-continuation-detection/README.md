# IMAP client continuation detection

This test verifies that synchronizing APPEND literals and the client lines used
by IDLE and multi-round AUTHENTICATE exchanges remain inspectable after the
initial command packet. It also checks alert direction and timing, continuation
ownership, credential redaction, and parsing of the next normal command.
