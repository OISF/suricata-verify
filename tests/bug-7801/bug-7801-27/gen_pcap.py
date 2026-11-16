#!/usr/bin/env python3
"""Generate PCAP for byte values kept when a file rule can't match a file.

One multipart POST to /up/42/ with two files:

  a.txt  "DATA42"                6 bytes
  b.bin  "DATA42-and-some-more" 20 bytes

Rule 2 takes v = 42 from http.uri, wants a file larger than 10 bytes, and checks
the two digits after "DATA" in file.data against v.

The first segment carries the request headers, all of a.txt and the boundary
line that closes it. So the rule's first pass on the transaction already reaches
the file engine: http.uri matches and produces v, and filesize reports that the
signature can't match this file. Inspect state is stored for that, because
another file may follow, and v has to be kept with it. When b.bin arrives the
rule is evaluated again with http.uri marked done, so v comes from the
transaction.

Rule 1 is inspected first on every pass and extracts "-" (45) from b.bin into
its own variable, which has the same local_id as v.

Without the value kept: rule 2 compares "42" with 45, no alert.
With it:                rule 2 alerts once.
"""
from scapy.all import IP, TCP, Raw, wrpcap

SRC, DST, SPORT, DPORT = "192.168.1.100", "192.168.1.1", 40028, 80
B = b"xyzBOUNDARYxyz"


def part(name, data):
    return (b"--" + B + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="' + name + b'"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n" + data + b"\r\n")


p1 = part(b"a.txt", b"DATA42")
p2 = part(b"b.bin", b"DATA42-and-some-more") + b"--" + B + b"--\r\n"
headers = (b"POST /up/42/ HTTP/1.1\r\nHost: example.com\r\n"
           b"Content-Type: multipart/form-data; boundary=" + B + b"\r\n"
           b"Content-Length: " + str(len(p1) + len(p2)).encode() + b"\r\n\r\n")
resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

# a multipart file is closed by the boundary line of the next part
boundary_line = b"--" + B + b"\r\n"
assert p2.startswith(boundary_line)
segments = (headers + p1 + boundary_line, p2[len(boundary_line):])

c, s = 100, 200
pkts = [IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="S", seq=c),
        IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="SA", seq=s, ack=c + 1)]
c += 1
s += 1
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c, ack=s))
for seg in segments:
    pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=c, ack=s) / Raw(load=seg))
    c += len(seg)
    pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="A", seq=s, ack=c))
    # acked data is inspected on the next packet in its direction
    pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c, ack=s))
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA", seq=s, ack=c) / Raw(load=resp))
s += len(resp)
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c, ack=s))
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="FA", seq=c, ack=s))
pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="FA", seq=s, ack=c + 1))
pkts.append(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=c + 1, ack=s + 1))
wrpcap("input.pcap", pkts)
