# Test Purpose

Verify that the 513th parsed email in one IMAP transaction is not retained,
raises the sticky `data_limit_reached` event, and does not prevent the tagged
response or a following transaction from completing.
