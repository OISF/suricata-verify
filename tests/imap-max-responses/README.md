With `max-responses` set to 3, a transaction keeps 3 response lines plus the
tagged reply that completes it. The first line past the limit raises
`imap.too_many_responses` once; a reply with exactly 3 lines raises nothing.
