This test verifies that a rejected synchronizing APPEND does not leave literal
state that consumes continuation data belonging to a later IDLE command. It
also includes a successful synchronizing APPEND as a control.

The rest of a command line after a literal was parsed but discarded, so an
argument such as a further SEARCH key never reached the `imap.request` buffer
or EVE.
