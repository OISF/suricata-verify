# Description

Tests SMB unicode named pipe.

# PCAP

The pcap comes from running Linux client smbclient against a Windows 2019 Server (with a shared folder public without needed authentication)

Command is
`smbclient //ServerIP/IPC$/ -U username%password -m NT1` where ServerIP is the IP address of the Windows server
