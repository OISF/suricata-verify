#!/usr/bin/env python
"""Generate a pcap that exercises the RB tree neighbour search in
DefragInsertFrag with frag_offset == 0 arriving while the tree is
non-empty.

The TCP payload is 40 bytes which, with the IPv4 header, gives three
8-byte fragments at offsets 0, 8 and 16. The fragments are written in
reverse order on the wire so the offset-0 fragment lands last and the
search at src/defrag.c:657 runs against a non-empty tree.

See Redmine #8232 and OISF/suricata PR #15403.
"""
from scapy.all import IP, TCP, fragment, wrpcap

payload = b"BUG8232-defrag-rb-key-underflow-regress\n"
packet = IP(src='1.1.1.1', dst='2.2.2.2', id=8232) / TCP(
        sport=12345, dport=8080, flags='PA', seq=1) / payload

frags = fragment(packet, fragsize=8)
frags.reverse()

wrpcap('frag-ip-tcp-payload.pcap', frags)
