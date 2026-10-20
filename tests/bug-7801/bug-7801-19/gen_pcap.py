#!/usr/bin/env python3
"""Generate PCAP for a consumer that is inspected before its producer.

Rule 1 reads v in http.stat_code, which is inspected first because it holds the
fast pattern, and only produces v later, in file.data. Its byte_test asks for
200 < v. Rule 2 is an ordinary rule that extracts 999 from the same body into
its own variable, which has the same local_id as v.

Two transactions, both "200 OK" with body "DATA999".

A variable that has not been produced reads 0, so rule 1 never matches: 200 < 0
is false. While a signature's slots were left as the last writer had them, rule
1 on the second transaction found the 999 that rule 2 left on the first one,
passed its byte_test, produced v and alerted.

Rule 1: 0 alerts. Rule 2: 2 alerts, one per transaction.
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC, DST, SPORT, DPORT = "192.168.1.100", "192.168.1.1", 40019, 80


def request(uri):
    return b"GET " + uri + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"


def response(body):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)


reqs = [request(u) for u in (b"/one", b"/two")]
resps = [response(b) for b in (b"DATA999", b"DATA999")]

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
