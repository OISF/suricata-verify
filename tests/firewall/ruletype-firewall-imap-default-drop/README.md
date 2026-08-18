Test that IMAP firewall default-drop policy works correctly.
The request_complete hook has no accept rule, so the first
completed IMAP transaction triggers the default app policy drop,
causing the flow to be dropped for all subsequent packets.
