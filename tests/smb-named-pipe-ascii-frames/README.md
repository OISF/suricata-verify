# Description

Tests SMB ascii named pipe instead of unicode.

# PCAP

The pcap comes from running Linux client smbclient against a Windows 2019 Server (with a shared folder public without needed authentication)

Needs a Proxy that sends the connexion smb packet without unicode flag.

Command is
`smbclient //localhost/IPC$/ -U username%password -m NT1`
