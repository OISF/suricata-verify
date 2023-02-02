# Description

Test SMB evasion with write data length lesser than NBSS record length (there is padding)

# PCAP

The pcap comes from running MacOS with a shared SMB directory named public (with user toto and password toto).
There is a proxy on port 4445 that rewrites the smb2 write command if the file data begins by 'E' to have a lesser field length.
Then fuzzpcap was used to split the write command in 2 tcp packets with an ACK in between, so that Suricata processes partial data.
