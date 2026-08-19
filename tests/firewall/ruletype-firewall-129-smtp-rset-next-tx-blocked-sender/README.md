SMTP firewall test: after an RSET the next transaction still occurs and is
judged on its own sender.

Same pcap as test 128 (MAIL FROM alice -> RSET -> MAIL FROM bob -> RCPT alice ->
DATA), but the policy only allows alice as a sender. The RSET-aborted first
transaction (alice) is validated and is NOT dropped. The second transaction
(bob) proceeds through MAIL FROM and RCPT and reaches DATA -- so it "occurred" --
and is only then dropped, because bob's sender is not allowed.

The drop lands on bob's own DATA, after alice's transaction was handled cleanly,
so the block is unambiguously caused by bob's sender policy, not by the RSET.
Compare with test 128, where the same second transaction is delivered when bob
is an allowed sender.

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

---> data          *** firewall drops the flow here ***
<--- 354 End data with <CR><LF>.<CR><LF>

---> (message body)
---> .
<--- 250 2.0.0 Ok: queued as <id>

---> QUIT
<--- 221 2.0.0 Bye
```

The pcap is a complete Postfix session captured without the firewall, so the server still replies to every command. In `--simulate-ips` Suricata applies the drop inline at the marked command; in a live deployment the rest of the session would not reach the server.
