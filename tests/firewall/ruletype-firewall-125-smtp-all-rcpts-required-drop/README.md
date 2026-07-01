SMTP firewall test using a single message with two RCPT TO commands:

- The sender is allowed.
- `alice@example.com` is an allowed recipient.
- `bob@example.com` is not an allowed recipient.

The firewall rules drop the connection when the disallowed recipient is
observed, even though another RCPT TO address in the transaction is allowed.
