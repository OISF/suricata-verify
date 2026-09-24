# Test Purpose

Verify that `app-layer.protocols.imap.max-tx=2` permits exactly two live IMAP
transactions and raises `too_many_transactions` when a third is attempted.
