This test verifies that a FETCH body supplied as a quoted string, such as
`* 1 FETCH (BODY[TEXT] "...")`, is extracted for email inspection just like a
literal body. An `email.body` rule matches the quoted body and, as a control,
the equivalent literal body. No parser error or `imap.invalid_data` event is
raised. Before the fix the quoted body was dropped and its rule missed.
