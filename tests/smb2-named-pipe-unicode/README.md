# Description

Tests SMBv2 named pipe.

# PCAP

The pcap comes from running Linux client smbclient against a Windows 10

Command is
`smbclient '\\ServerIP\IPC$ -U domain\\username` where ServerIP is the IP address of the Windows 10 server
