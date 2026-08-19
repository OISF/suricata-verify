SMTP firewall test with interactive/no-op commands interspersed with a valid
message.

The client issues NOOP, VRFY, EXPN and HELP before and during the envelope.
Those commands do not carry an envelope, so they neither satisfy nor break the
sender/recipient validation. The real MAIL FROM / RCPT TO still validate and
the message is delivered.

## SMTP session

The SMTP dialog in the pcap (`--->` client, `<---` server):

```
<--- 220 mail.example.com ESMTP Postfix

---> helo client.example.com
<--- 250 mail.example.com

---> NOOP
<--- 250 2.0.0 Ok

---> VRFY bob
<--- 252 2.0.0 bob

---> EXPN staff
<--- 500 5.5.2 Error: command not recognized

---> HELP
<--- 500 5.5.2 Error: command not recognized

---> mail from:<alice@example.com>
<--- 250 2.1.0 Ok

---> NOOP
<--- 250 2.0.0 Ok

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
