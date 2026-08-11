# Description

SMTP BDAT (CHUNKING) with a message split across two valid chunks, followed by
a second message on the same connection. BDAT octet accounting is per chunk;
the second chunk must not inherit the first chunk's byte count and raise
`BDAT_CHUNK_LEN_EXCEEDED`, which would terminate SMTP parsing and leave the
following message uninspected.

Redmine ticket: https://redmine.openinfosecfoundation.org/issues/8741

# PCAP

The synthetic pcap was supplied by the reporter. The important sequence is:

```
<--- 250 CHUNKING

---> MAIL FROM:<a@example.com>
<--- 250 OK
---> RCPT TO:<b@example.com>
<--- 250 OK
---> BDAT 79
---> (first 79 octets)
<--- 250 79 octets received
---> BDAT 44 LAST
---> (final 44 octets)
<--- 250 message accepted

---> MAIL FROM:<evil@example.com>
<--- 250 OK
---> RCPT TO:<victim@example.com>
<--- 250 OK
---> DATA
<--- 354 go
---> Subject: SECOND-MAIL-MARKER
---> (message body)
---> .
<--- 250 queued
```

The test checks that no anomaly is raised, both message transactions are
logged, and an `email.subject` rule alerts on the marker in the second message.
The alert proves SMTP inspection continues after the valid multi-chunk BDAT
message.
