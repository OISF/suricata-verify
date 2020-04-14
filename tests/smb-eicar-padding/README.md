# Description

Test SMB EICAR file rule with padding evasion.

# PCAP

The pcap comes from running Linux client smbclient against a Windows 2019 Server (with a shared forlder public wihtout needed authentication)
Command is
`smbclient //192.168.1.3/public/ -U % -m NT1`
Than in the smbclient shell :
`put eicar` where eicar is the name of a file with the EICAR contents :
https://en.wikipedia.org/wiki/EICAR_test_file

The proxy changes the Write request with adding a dummy padding (by increasing unnecessarly the data_offset)

