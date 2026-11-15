# Description

Modbus/TCP gap recovery: after a TCP gap the parser resumes at the next
plausible MBAP header instead of disabling Modbus parsing for the rest of the
flow.

- 40001: a request and its response are lost; the later transactions are parsed.
- 40002: only a response is lost; its request is closed without one.
- 40003: the first half of a request is lost; its tail is skipped, and its
  response is not reported as unsolicited.

## PCAP

Generated with `create-pcap.py` (Scapy).

## Ticket

https://redmine.openinfosecfoundation.org/issues/3554
