#!/usr/bin/env python3
# Generates input.pcap: one established connection with a single 20 byte
# payload sent from the client.
#
# The payload starts with a 4 byte big endian length field with the value 8,
# then "TARGET", 2 filler bytes, "TARGET" again and 2 filler bytes:
#
#   00 00 00 08 54 41 52 47 45 54 41 42 54 41 52 47 45 54 43 44
#   <length > <- 4 ->  <- 2 -> <- 4 ->  <- 2 ->
#
# byte_extract and byte_math stop right after the 4 bytes they read, so the
# detection pointer ends up at offset 4. byte_jump:4,0 jumps the value it read
# (8) plus the 4 bytes it read, so the pointer ends up at offset 12. Both
# offsets are the start of one of the two "TARGET" strings.
from scapy.all import Ether, IP, TCP, wrpcap

payload = b"\x00\x00\x00\x08" + b"TARGET" + b"AB" + b"TARGET" + b"CD"
assert len(payload) == 20

client = Ether(src="00:01:02:03:04:05", dst="00:0a:95:9f:67:66") / IP(
    src="10.0.0.1", dst="10.0.0.2"
)
server = Ether(src="00:0a:95:9f:67:66", dst="00:01:02:03:04:05") / IP(
    src="10.0.0.2", dst="10.0.0.1"
)
cport, sport = 1234, 80
cseq, sseq = 1000, 2000

pkts = [
    client / TCP(sport=cport, dport=sport, flags="S", seq=cseq),
    server / TCP(sport=sport, dport=cport, flags="SA", seq=sseq, ack=cseq + 1),
    client / TCP(sport=cport, dport=sport, flags="A", seq=cseq + 1, ack=sseq + 1),
    client / TCP(sport=cport, dport=sport, flags="PA", seq=cseq + 1, ack=sseq + 1) / payload,
    server / TCP(sport=sport, dport=cport, flags="A", seq=sseq + 1, ack=cseq + 1 + len(payload)),
]

wrpcap("input.pcap", pkts)
