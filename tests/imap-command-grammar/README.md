This test verifies that the list wildcards `%` and `*` are accepted unquoted
in LIST and LSUB mailbox patterns, as sent by most clients when enumerating
folders, without raising a parser error or an `imap.invalid_data` event. It
also checks that sequence sets still parse and that parsing continues with
the following commands.

STORE accepts an unparenthesized system-flag list, such as
`A1 STORE 1 +FLAGS \Seen`, including several space-separated flags and the
`.SILENT` form, without raising a parser error or an `imap.invalid_data` event.
A parenthesized STORE serves as control, and a following command confirms that
parsing continues.

Escaped quotes and backslashes are accepted in IMAP
quoted strings, and that parentheses inside quoted strings do not end request
lists or FETCH responses.
