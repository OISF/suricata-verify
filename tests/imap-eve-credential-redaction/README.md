# IMAP EVE credential redaction

This test verifies that quoted and synchronizing-literal LOGIN credentials and
SASL initial responses are redacted from default IMAP EVE output. It also
covers the existing behavior that omits client responses to SASL continuation
requests.
