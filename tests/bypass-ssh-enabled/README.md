# Test Description

Tests that the encrypted part of the SSH traffic is bypassed but it should not
bypass based on the depth

## PCAP

Source: https://www.cloudshark.org/captures/9b72eb8febf9
File: ssh-server-client.pcapng

## Related issues

Created with a work to decouple stream.bypass setting from TLS encrypted bypass.
https://redmine.openinfosecfoundation.org/issues/6788
