# Description

Test SMB evasion with write data length bigger than NBSS record length

# PCAP

The pcap comes from running MacOS with a shared SMB directory named public (with user toto and password toto).
There is a proxy on port 4445 that rewrites the smb2 write command if the file data begins by 'E' to have a bigger field length.
