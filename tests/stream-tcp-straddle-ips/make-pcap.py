#!/usr/bin/env python3
# Generates stream-tcp-straddle-ips.pcap
#
# Flow 1, 10.0.0.1:33333 -> 10.0.0.2:12345: the toserver stream is
# A*16384, K*16383 + Q, E*512. Packets 9-11 retransmit parts of it with
# different heads: in IPS mode the overlap is rewritten in place from the
# stored stream data. The stream base stays unslid here.
#
# Flow 2, 10.0.0.3:44444 -> 10.0.0.4:53 (DNS over TCP): the app layer
# consumes only the first query, so the stream base slides past the head of
# the stored segment. The retransmit at base_seq then overlaps a segment
# whose head was pruned: a correct rewrite puts the stored DNS length prefix
# (05 00) in front, while on pre-fix code the copy starts 25 bytes too far
# into the stored data (LM).
import struct
import string
from scapy.all import Ether, IP, TCP, wrpcap

m1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
    IP(src="10.0.0.1", dst="10.0.0.2")
m2 = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / \
    IP(src="10.0.0.2", dst="10.0.0.1")
m3 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
    IP(src="10.0.0.3", dst="10.0.0.4")
m4 = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / \
    IP(src="10.0.0.4", dst="10.0.0.3")

def tcp(flags, seq, ack=0, payload=b"", sport=33333, dport=12345):
    return TCP(sport=sport, dport=dport, flags=flags, seq=seq,
               ack=ack, window=65535) / payload

def c(flags, seq, ack=0, payload=b""):
    return m1 / tcp(flags, seq, ack, payload)

def s(flags, seq, ack=0, payload=b""):
    return m2 / tcp(flags, seq, ack, payload, sport=12345, dport=33333)

def c2(flags, seq, ack=0, payload=b""):
    return m3 / tcp(flags, seq, ack, payload, sport=44444, dport=53)

def s2(flags, seq, ack=0, payload=b""):
    return m4 / tcp(flags, seq, ack, payload, sport=53, dport=44444)

def dns_query(qname=b"\x01a\x03com\x00", ident=0x1234):
    body = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    body += qname + b"\x00\x01\x00\x01"
    return struct.pack(">H", len(body)) + body

pkts = [
    # flow 1: handshake
    c("S", 1000),
    s("SA", 2000, 1001),
    c("A", 1001, 2001),
    # accepted data
    c("A", 1001, 2001, b"A" * 16384),   # [1001, 17385)
    s("A", 2001, 17385),
    c("A", 17385, 2001, b"K" * 16383 + b"Q"),  # [17385, 33769), byte 33768 is Q
    s("A", 2001, 33769),
    # new data
    c("A", 33769, 2001, b"E" * 512),    # [33769, 34281)
    # retransmit overlapping the stored segment, different data
    c("A", 33000, 2001, b"C" * 1024),   # [33000, 34024)
    # same range, different data again
    c("A", 33000, 2001, b"D" * 1024),   # [33000, 34024)
    # retransmit of the overlap tail; head byte 33768 is Q in the
    # stored stream: the rewrite must put Q in front
    c("A", 33768, 2001, b"H" * 256),    # [33768, 34024)
    # close the flow so the flow event is logged
    c("F", 34281, 2001),
    s("FA", 2001, 34282),
    c("A", 34282, 2002),
    s("A", 2002, 34282),
]

# flow 2: one complete DNS query and a truncated second message
pat = (string.ascii_uppercase + string.ascii_lowercase + string.digits).encode()
msg = dns_query()
tail = struct.pack(">H", 1280) + struct.pack(">HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0)
n = len(tail)
tail += bytes(pat[(i - n) % len(pat)] for i in range(n, 900))
data2 = msg + tail                      # [5001, 5001 + 925)
end2 = 5001 + len(data2)

pkts += [
    c2("S", 5000),
    s2("SA", 6000, 5001),
    c2("A", 5001, 6001),
    c2("A", 5001, 6001, data2),
    # ack only the parsed query: base_seq can slide up to here
    s2("A", 6001, 5001 + len(msg)),
    # more of the truncated second message: the prune after this packet
    # slides base_seq to 5001 + len(msg)
    c2("A", end2, 6001, b"q" * 20),
    # retransmit at base_seq, different data: must be rewritten from the
    # stored data at base_seq (05 00), not 25 bytes further (LM)
    c2("A", 5001 + len(msg), 6001, b"WW"),
    # close the flow so the flow event is logged
    c2("F", end2 + 20, 6001),
    s2("FA", 6001, end2 + 21),
    c2("A", end2 + 21, 6002),
    s2("A", 6002, end2 + 21),
]

# fixed timestamps so regenerating the pcap is reproducible
for i, pkt in enumerate(pkts):
    pkt.time = 1700000000.0 + i * 0.001

wrpcap("stream-tcp-straddle-ips.pcap", pkts)
