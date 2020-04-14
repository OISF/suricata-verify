# Description

Test SMB EICAR file rule with file overlap evasion.

# PCAP

The pcap comes from running Linux client smbclient against a Windows 2019 Server (with a shared forlder public wihtout needed authentication)
Command is
`smbclient //192.168.1.3/public/ -U % -m NT1`
Than in the smbclient shell :
`put eicar` where eicar is the name of a file with the EICAR contents :
https://en.wikipedia.org/wiki/EICAR_test_file

The proxy changes the Write request with :
- a first dummy write of one byte at offset 0 is done
- the second full write of EICAR at offset 0 is then done and does not trigger detection

Now, an event is set for file overlaps.
