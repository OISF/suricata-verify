# Description

Test smtp RSET support.

# PCAP

The pcap comes from running postfix 3.4.5 as a server and the present dummy python script client.py
The client sends 2 mails (with BDAT) in one connection with RSET in between
The point is to test that Suricata resets its smtp state
