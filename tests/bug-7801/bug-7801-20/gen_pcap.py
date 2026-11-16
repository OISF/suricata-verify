#!/usr/bin/env python3
"""Generate PCAP for byte_jump using a variable from another buffer.

Rule: http.uri produces off, file.data does byte_jump:1,off,string,dec and then
looks for "END" within 3 bytes of where the jump lands.

Both responses carry "AB3xyzEND". With off = 2 the jump reads "3" and skips
"xyz", landing on "END". With off = 0 it reads "A", which is not a number.

TX1: GET /j/2/  -> off = 2 -> alert.
TX2: GET /j/0/  -> off = 0 -> no alert. Pipelined, so its producer runs before
                  TX1's file.data and leaves 0 in the thread's slot.

Without per-transaction values: TX1 jumps from offset 0, 0 alerts.
With them:                      1 alert, on TX1.
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC, DST, SPORT, DPORT = "192.168.1.100", "192.168.1.1", 40020, 80


def request(uri):
    return b"GET " + uri + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"


def response(body):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)


reqs = [request(u) for u in (b"/j/2/", b"/j/0/")]
resps = [response(b) for b in (b"AB3xyzEND", b"AB3xyzEND")]

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
