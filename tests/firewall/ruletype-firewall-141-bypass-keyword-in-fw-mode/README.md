# Test

Ensure that the engine accepts the `bypass` keyword in a firewall rule.

The accepted firewall rule matches the decoded HTTP host
`www.testmyids.com`, then accepts and bypass the flow at the
`http1:request_headers` hook.

## Ticket

Related to
https://redmine.openinfosecfoundation.org/issues/8459.
