Test that IMAP firewall mode works with all hooks accepted.
All four IMAP hooks (request_in_progress, request_complete,
response_in_progress, response_complete) have accept rules,
so no drops should occur and IMAP parsing should complete normally.
