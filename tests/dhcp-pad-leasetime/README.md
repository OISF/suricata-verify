# DHCP PAD before lease time

This test verifies that DHCP option 0 is parsed as a single-byte
option.
The DHCP ACK in `input.pcap` contains a PAD immediately before a lease-time option.
