# Description

Test SMB EICAR file rule.

# PCAP

The pcap comes from running Linux client smbclient against a Windows 2019 Server (with a shared folder public without needed authentication)

Needs a Proxy that sends two netbios requests in one segment

Command is
`smbclient //localhost/public/ -U % -m NT1`
Than in the smbclient shell :
`put eicar` where eicar is the name of a file with the EICAR contents :
https://en.wikipedia.org/wiki/EICAR_test_file
