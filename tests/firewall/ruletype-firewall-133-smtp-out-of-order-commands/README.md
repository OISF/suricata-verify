SMTP firewall test: out-of-order commands (RCPT TO before MAIL FROM, and DATA
before a valid recipient), then a valid envelope.

The out-of-order RCPT TO opens transaction 0 and matches the recipient rule
(sid 1999), setting fw.smtp.rcpt_to_ok. The out-of-order DATA then advances that
same transaction to request_data before any MAIL FROM has been validated, so
fw.smtp.mail_from_ok is never set. The request_data rule (sid 2005) requires
both xbits, so it fails on the missing sender xbit and the firewall fails closed
and drops the flow. The later valid envelope is never delivered.

## SMTP session

The SMTP dialog in the pcap (`--->` client, `<---` server):

```
<--- 220 mail.example.com ESMTP Postfix

---> helo client.example.com
<--- 250 mail.example.com

---> rcpt to:<bob@example.com>
<--- 503 5.5.1 Error: need MAIL command

---> data          *** firewall drops the flow here ***
<--- 503 5.5.1 Error: need RCPT command

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

The pcap is a complete Postfix session captured without the firewall, so the
server still replies to every command. In `--simulate-ips` Suricata applies the
drop inline at the marked command; in a live deployment the rest of the session
would not reach the server.
