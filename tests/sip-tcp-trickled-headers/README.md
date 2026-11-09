# Description

Two valid SIP requests with many headers, sent over TCP one byte per segment,
must both be parsed. The parser waits for the end of the headers instead of
parsing the whole pending message again on each new segment.

The test only checks that the messages are parsed: the quadratic cost of
parsing them again on each segment is not visible in the output.

# PCAP

Created with `create_pcap.py`.

# Ticket

https://redmine.openinfosecfoundation.org/issues/9101
