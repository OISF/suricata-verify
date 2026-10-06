#!/usr/bin/env python3
# One HTTP/1.1 flow whose request is a multipart/form-data upload with
# two file parts; the htp parser opens a file per part (request-
# direction mime extraction), so the file log callback (and the
# File::file_store_id assignment in the filedata path) runs once per
# file.
from scapy.all import IP, TCP, Raw, wrpcap, Ether

def ip(s, d):
    return Ether() / IP(src=s, dst=d)

B = b"BOUNDB36543"
part1 = b"A1a2B3b4C5c6D7d8"
part2 = b"feedfacecafebabe"
body = (b"--" + B + b"\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: form-data; name=\"file1\"; filename=\"part1.bin\"\r\n"
        b"\r\n" + part1 + b"\r\n"
        b"--" + B + b"\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: form-data; name=\"file2\"; filename=\"part2.bin\"\r\n"
        b"\r\n" + part2 + b"\r\n"
        b"--" + B + b"--\r\n")
req = (b"POST /upload HTTP/1.1\r\n"
       b"Host: example.com\r\n"
       b"Content-Type: multipart/form-data; boundary=\"" + B + b"\"\r\n"
       b"Content-Length: " + str(len(body)).encode() + b"\r\n"
       b"\r\n" + body)
resp = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"

pkts = [
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="S", seq=1000),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001) /
        Raw(load=req),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=49152, flags="PA", seq=5001, ack=1001 + len(req)) /
        Raw(load=resp),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="A", seq=1001 + len(req),
        ack=5001 + len(resp)),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="F", seq=1001 + len(req),
        ack=5001 + len(resp)),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=49152, flags="FA", seq=5001 + len(resp),
        ack=1002 + len(req)),
]
wrpcap("input.pcap", pkts)
print("wrote input.pcap (%d bytes body)" % len(body))
