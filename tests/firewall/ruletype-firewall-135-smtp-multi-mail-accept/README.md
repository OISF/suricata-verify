SMTP firewall test: three back-to-back messages in a single TCP session.

With an @example.com sender policy, each of the three transactions is validated
independently and all three messages are delivered:

- alice@example.com -> bob@example.com
- bob@example.com -> alice@example.com
- alice@example.com -> bob@example.com, alice@example.com

See test 136 for the same pcap under an alice-only sender policy.

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

---> data
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
