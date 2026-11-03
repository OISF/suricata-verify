#!/usr/bin/env python3
"""Generate PCAP for a content distance taken from another buffer.

Rule: http.uri produces dist, file.data matches "AA" and then "ZZ" with
distance:dist and within:2. Both responses carry "AAxxxZZ", so "ZZ" is found
only when dist is exactly 3.

TX1: GET /d/3/ -> dist = 3 -> alert.
TX2: GET /d/1/ -> dist = 1 -> no alert. Pipelined, so its producer runs before
                 TX1's file.data and leaves 1 in the thread's slot.

Without per-transaction values: TX1 looks at distance 1, 0 alerts.
With them:                      1 alert, on TX1.
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC, DST, SPORT, DPORT = "192.168.1.100", "192.168.1.1", 40021, 80


def request(uri):
    return b"GET " + uri + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"


def response(body):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)


reqs = [request(u) for u in (b"/d/3/", b"/d/1/")]
resps = [response(b) for b in (b"AAxxxZZ", b"AAxxxZZ")]

c, s = 100, 200
pkts = [IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="S", seq=c),
        IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="SA", seq=s, ack=c + 1)]
c += 1
s += 1
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c, ack=s))
# both requests go out before any response: two transactions, one flow
for r in reqs:
    pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c, ack=s) / Raw(load=r))
    c += len(r)
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="A", seq=s, ack=c))
for r in resps:
    pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA", seq=s, ack=c) / Raw(load=r))
    s += len(r)
    pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c, ack=s))
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="FA", seq=c, ack=s))
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="FA", seq=s, ack=c + 1))
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c + 1, ack=s + 1))

wrpcap("input.pcap", pkts)
