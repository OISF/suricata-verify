SMTP firewall test: RSET after RCPT TO discards the envelope, then a fresh,
complete envelope from the same allowed sender is sent and delivered.

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

---> RSET
<--- 250 2.0.0 Ok

---> mail from:<alice@example.com>
<--- 250 2.1.0 Ok

---> rcpt to:<bob@example.com>
<--- 250 2.1.5 Ok

---> data
<--- 354 End data with <CR><LF>.<CR><LF>

---> (message body)
---> .
<--- 250 2.0.0 Ok: queued as <id>

---> QUIT
<--- 221 2.0.0 Bye
```
