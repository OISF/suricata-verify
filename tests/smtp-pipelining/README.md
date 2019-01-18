# Description

Test smtp pipelining support.

# PCAP

The pcap comes from running postfix as a server and the present dummy python script client.py
The postfix server advertises pipelining support in the pcap and accepts all commands MAIL FROM, RCPT TO and DATA in one packet, and returns only one answer.
