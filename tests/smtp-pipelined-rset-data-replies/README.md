# Description

Protocol-minimized regression test for Redmine Bug #8739:

https://redmine.openinfosecfoundation.org/issues/8739

Originally found by OSS-Fuzz testcase 5498180758994944:

https://oss-fuzz.com/testcase?key=5498180758994944

# PCAP

The 13-packet capture is a protocol-minimized derivative of the original
`fuzz_sigpcap_aware` input. The fuzzpcap stream was converted to a regular
pcap and reduced to this SMTP dialog (`--->` client, `<---` server):

```
<--- 220 mail.example ESMTP ready

---> EHLO client.example
<--- 250-PIPELINING
<--- 250 OK

---> RSET
---> DATA
---> .

<--- 250 reset
<--- 354 continue
<--- 250 queued
```

The `RSET`, `DATA`, and `.` lines are pipelined in one client packet. Each
server reply is sent separately.
