# Test Description

An open frame that starts past stream offset 2500 must be inspected in
2500-byte steps, like a frame near the start of the stream.

The pcap is an SMTP session with two messages. The second message's
`smtp.data` frame starts at stream offset 3401, and its 22 KB body
arrives one line per segment. A `frame:smtp.data` content rule alerts 9
times on it, once per 2500 bytes. Before the fix, the inspection check
compared the frame-relative inspection progress with an absolute stream
offset, so the frame was inspected, and the rule alerted, on every
segment (2000 alerts).

## PCAP

Created with `writepcap.py` (scapy).

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/9444
