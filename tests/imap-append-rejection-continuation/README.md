# IMAP rejected APPEND continuation handling

This test verifies that a rejected synchronizing APPEND does not leave literal
state that consumes continuation data belonging to a later IDLE command. It
also includes a successful synchronizing APPEND as a control.
