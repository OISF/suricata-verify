# Description

Test SSH parsing against banner end of line splitting.

# PCAP

The pcap comes from `ssh pi@192.168.1.12 -p 2222` where the proxy from `proxy.py` listens and redirects packets to Raspberry Pi OpenSSH server located at 192.168.1.40
The script proxy.py splits the banner request in two packets in the middle of the CRLF end of line.
