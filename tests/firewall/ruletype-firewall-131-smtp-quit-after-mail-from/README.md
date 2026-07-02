SMTP firewall test: QUIT immediately after MAIL FROM.

The envelope is abandoned before any recipient and before DATA, so the
transaction never advances to the request_data (DATA) state.

The ruleset is intentionally minimal: it accepts every hook and adds a tripwire
rule (sid 2006) that alerts on any transition to request_data. The check asserts
this alert never fires; if an abandoned envelope ever advanced to DATA, the
alert would fire and this test would fail.

## SMTP session

The SMTP dialog in the pcap (`--->` client, `<---` server):

```
<--- 220 mail.example.com ESMTP Postfix

---> helo client.example.com
<--- 250 mail.example.com

---> mail from:<alice@example.com>
<--- 250 2.1.0 Ok

---> QUIT
<--- 221 2.0.0 Bye
```
