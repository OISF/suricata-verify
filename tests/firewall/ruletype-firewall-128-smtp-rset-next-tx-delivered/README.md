SMTP firewall test: an RSET must not block the next transaction from occurring.

After MAIL FROM alice the client issues RSET, then starts a second, different
envelope: MAIL FROM bob -> RCPT alice -> DATA. Under a policy that allows any
@example.com sender, the second transaction (from bob) is validated on its own
and delivered. The RSET only aborted the first envelope; it did not block the
second one.

The second sender differs from the first, which shows the second transaction is
inspected independently (a fresh per-tx validation), not carried through on the
first envelope's state. See test 129 for the same pcap under an alice-only
policy, where the second transaction still occurs but is blocked on its own
sender.

## SMTP session

The SMTP dialog in the pcap (`--->` client, `<---` server):

```
<--- 220 mail.example.com ESMTP Postfix

---> helo client.example.com
<--- 250 mail.example.com

---> mail from:<alice@example.com>
<--- 250 2.1.0 Ok

---> RSET
<--- 250 2.0.0 Ok

---> mail from:<bob@example.com>
<--- 250 2.1.0 Ok

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
