#!/usr/bin/env python3
from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_IP, SERVER_IP = "192.0.2.21", "192.0.2.22"
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:21", "02:00:00:00:00:22"
CPORT, SPORT = 40243, 143

def pkt(server, seq, ack, flags, payload=b""):
    if server:
        sm, dm, si, di, sp, dp = SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, SPORT, CPORT
    else:
        sm, dm, si, di, sp, dp = CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CPORT, SPORT
    p = Ether(src=sm, dst=dm) / IP(src=si, dst=di) / TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
    return p / Raw(load=payload) if payload else p

greeting = b"* OK IMAP ready\r\n"
request = b"A1 NOOP\r\n"
untagged = b"".join(b"* %d EXISTS\r\n" % i for i in range(1, 513))
completion = b"A1 OK NOOP completed\r\n"
request2 = b"A2 NOOP\r\n"
completion2 = b"A2 OK NOOP completed\r\n"
cs, ss = 1000, 9000
packets = [
    pkt(False, cs, 0, "S"), pkt(True, ss, cs + 1, "SA"),
    pkt(False, cs + 1, ss + 1, "A"),
    pkt(True, ss + 1, cs + 1, "PA", greeting),
    pkt(False, cs + 1, ss + 1 + len(greeting), "PA", request),
    pkt(True, ss + 1 + len(greeting), cs + 1 + len(request), "PA", untagged),
    pkt(True, ss + 1 + len(greeting) + len(untagged), cs + 1 + len(request), "PA", completion),
    pkt(False, cs + 1 + len(request), ss + 1 + len(greeting) + len(untagged) + len(completion), "PA", request2),
    pkt(True, ss + 1 + len(greeting) + len(untagged) + len(completion), cs + 1 + len(request) + len(request2), "PA", completion2),
]
for timestamp, p in enumerate(packets, 1):
    p.time = timestamp
wrpcap("input.pcap", packets)
