# Description

Test SMB2 file deletion logging.

# PCAP

The pcap comes from running Macos client smbclient against a Windows 2019 Server (with a public shared folder without needed authentication)
Commands on the client are
```
mount_smbfs "//GUEST@192.168.1.51/sand" tmp
ls tmp/
echo "to remove" > tmp/test
rm tmp/test
umount tmp
```
