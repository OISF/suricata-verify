SMTP firewall test: a nested MAIL FROM (a second MAIL FROM before RSET or DATA).

The server rejects the nested MAIL FROM (503) and the original, allowed sender
remains in effect. The firewall keeps the validated envelope and the message is
delivered.

## SMTP session

The SMTP dialog in the pcap (`--->` client, `<---` server):

```
<--- 220 mail.example.com ESMTP Postfix

---> helo client.example.com
<--- 250 mail.example.com

---> mail from:<alice@example.com>
<--- 250 2.1.0 Ok

---> mail from:<bob@example.com>
<--- 503 5.5.1 Error: nested MAIL command

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
