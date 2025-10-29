#Description

This test verifies Suricata's detection and handling of NFSv2 WRITE operations.
It uses a pcap containing NFSv2 WRITE traffic and checks that:
 - NFSv2 WRITE is decoded and reported in `nfs` events
 - A `fileinfo` event is produced with `nfs.file_tx: true`
 - The written file content is stored with correct size (6 bytes) and SHA256 hash
 - A filestore-backed alert triggers and a file is stored on disk

Expected written data: "hallo\n" (6 bytes)
SHA256: 622cb3371c1a08096eaac564fb59acccda1fcdbe13a9dd10b486e6463c8c2525

Minimum Suricata version required: 9

Files in this directory:
- `test.yaml` — Test configuration (references the pcap below)
- `test.rules` — Suricata rule to trigger an NFS filestore alert

# PCAP source
- The `test.yaml` references `../issue-3277-nfsv2-filestore/nfsv2.pcap`

#Related Issue
https://redmine.openinfosecfoundation.org/issues/4946