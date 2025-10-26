#Description

This test verifies Suricata’s detection of NFSv2 WRITE operations.
It uses a pcap containing NFSv2 WRITE traffic and checks that Suricata generates the expected alert when processing these operations.
This ensures that NFSv2 WRITE support is correctly implemented and tested in Suricata.

Files in this directory:
- test.yaml - Test configuration (references the pcap below)
- test.rules - Suricata rule to trigger an NFS filestore alert

#PCAP source:
- The test.yaml references ../issue-3277-nfsv2-filestore/nfsv2.pcap

#Related Issue
https://redmine.openinfosecfoundation.org/issues/4946