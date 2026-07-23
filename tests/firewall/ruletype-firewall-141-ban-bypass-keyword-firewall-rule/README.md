# Test

Ensure that the engine rejects the `bypass` keyword in a firewall rule.

The rejected firewall rule would match the decoded HTTP host
`www.testmyids.com`, then accept and bypass the flow at the
`http1:request_headers` hook. The retained event checks document the behavior
expected if bypass support is enabled in the future.

This ticket also contains valid checks for if the bypass were to be allowed in
firewall mode.

## Ticket

Related to
https://redmine.openinfosecfoundation.org/issues/8459.
