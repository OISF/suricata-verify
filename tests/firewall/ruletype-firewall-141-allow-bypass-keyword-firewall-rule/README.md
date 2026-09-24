# Test

Updated test to ensure that the engine accepts the `bypass` keyword in a firewall
mode, in a firweall rule.

The accepted firewall rule matches the decoded HTTP host
`www.testmyids.com`, then accepts and bypasses the flow at the
`http1:request_headers` hook.

## Ticket

Related to
https://redmine.openinfosecfoundation.org/issues/8459.
