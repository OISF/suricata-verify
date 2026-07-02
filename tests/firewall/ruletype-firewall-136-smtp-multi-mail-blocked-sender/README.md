SMTP firewall test: three back-to-back messages in a single TCP session under
an alice-only sender policy.

- Message 1 (alice -> bob) is validated and delivered.
- Message 2 (bob -> alice) fails sender validation. Because DATA is disallowed
  for the unvalidated transaction, the firewall drops the flow.
- Message 3 (alice -> bob, alice) would be allowed, but the flow is already
  dropped, so it is never delivered.

This shows that a single policy-violating message in a back-to-back session
takes down the rest of the session (fail-closed flow drop). See test 135 for
the accepting policy.

## SMTP session

The SMTP dialog in the pcap (`--->` client, `<---` server):

```
<--- 220 mail.example.com ESMTP Postfix

---> helo client.example.com
<--- 250 mail.example.com

---> mail from:<alice@example.com>
<--- 250 2.1.0 Ok

---> rcpt to:<bob@example.com>
<--- 250 2.1.5 Ok

---> data
<--- 354 End data with <CR><LF>.<CR><LF>

---> (message body)
---> .
<--- 250 2.0.0 Ok: queued as <id>

---> mail from:<bob@example.com>
<--- 250 2.1.0 Ok

---> rcpt to:<alice@example.com>
<--- 250 2.1.5 Ok

---> data          *** firewall drops the flow here ***
<--- 354 End data with <CR><LF>.<CR><LF>

---> (message body)
---> .
<--- 250 2.0.0 Ok: queued as <id>

---> mail from:<alice@example.com>
<--- 250 2.1.0 Ok

---> rcpt to:<bob@example.com>
<--- 250 2.1.5 Ok

---> rcpt to:<alice@example.com>
<--- 250 2.1.5 Ok

---> data
<--- 354 End data with <CR><LF>.<CR><LF>

---> (message body)
---> .
<--- 250 2.0.0 Ok: queued as <id>

---> QUIT
<--- 221 2.0.0 Bye
```

The pcap is a complete Postfix session captured without the firewall, so the
server still replies to every command. In `--simulate-ips` Suricata applies the
drop inline at the marked command; in a live deployment the rest of the session
would not reach the server.
