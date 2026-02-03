# Test Purpose

Verify that `email.*` inspection covers every email returned by one
multi-message IMAP FETCH transaction.

The first fetched email contains a control body marker. The second fetched
email contains unique body and subject markers. All three markers must alert.

