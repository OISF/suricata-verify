This test verifies that the `imap.headers` and `imap.body` frames of an
APPEND literal are created whether the literal arrives in one segment or is
split inside the body or inside the header section, and that the `imap.pdu`
frame spans the whole literal. A FETCH literal split across two server
segments serves as control. The uploaded message must still be parsed, no
parser error or `imap.invalid_data` event may be raised, and parsing must
continue afterwards.
