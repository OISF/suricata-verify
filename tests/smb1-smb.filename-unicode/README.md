# Description

Tests SMBv1 unicode create filename.

# PCAP

The pcap comes from running Linux client smbclient against a Windows 7

Command is
`smbclient '\\<ip>\C$' -U '<domain>\\<username>%<password>' -m NT1 --option='client min protocol=NT1' --command='get a.txt'`
