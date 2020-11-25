# Description

Test SMB EICAR file rule with AndX evasion.

# PCAP

The pcap comes from running Linux client smbclient against a server which is a Windows10 with public shared folder named catena without password
Command is
`smbclient -p 4445 //192.168.1.12/catena/ -U" "%" " -m NT1`
Than in the smbclient shell :
`put eicar` where eicar is the name of a file with the EICAR contents :
https://en.wikipedia.org/wiki/EICAR_test_file

cf https://redmine.openinfosecfoundation.org/issues/3475

The proxy changes the Write request with chained AndX commands :
- Locking
- Write
- Close

and putting the data written to the file after the Close Request
