# Redmine #8835 oversized conditional pcap-log segment

Regression test for https://redmine.openinfosecfoundation.org/issues/8835.

The generator follows the ticket's packet layout: a normal handshake, one
Ethernet/IPv4/TCP frame with an IPv4 total length of 65,535 bytes, and a server
acknowledgement. The alert enables conditional segment replay. Before the fix,
the 65,549-byte reconstructed frame was truncated into a 65,535-byte
`MemBuffer`, while libpcap was told to read the full length, producing an ASAN
heap over-read. A fixed build expands the buffer and writes the complete pcap.

Regenerate the pcap with `./make-pcap.py`.
