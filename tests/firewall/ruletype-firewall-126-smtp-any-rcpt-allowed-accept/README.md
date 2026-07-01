SMTP firewall test using the same two-recipient pcap as test 125:

- The sender is allowed.
- `alice@example.com` is an allowed recipient.
- `bob@example.com` is not matched by the recipient allow rule.

The firewall rules accept the full connection because this policy allows the
transaction when any RCPT TO in the transaction is allowed.
