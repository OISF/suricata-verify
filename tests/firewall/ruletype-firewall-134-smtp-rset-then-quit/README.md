SMTP firewall test: build a complete envelope, then RSET it away and QUIT
without ever sending a message.

The envelope (allowed sender and recipient) is validated and logged, no DATA is
transferred, and nothing is dropped.

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

---> QUIT
<--- 221 2.0.0 Bye
```
