#!/usr/bin/env python3
# An HTTP transaction with a file in each direction, both truncated,
# and the pcap ends without FINs: the ts stream has the multipart
# upload (headers + one unterminated part) and the tc stream the
# download (8 of 100 declared bytes). At end of pcap Suricata forces
# the reassembly pseudo passes: a toserver pseudo for the pending ts
# stream and a toclient pseudo (the last one, so eof) for the tc
# stream, and the file loggers run from those passes. The file handle
# must anchor the logger's dir (the file container's direction), not
# the running packet's: on the eof pass the two containers are driven
# from pseudo packets and the handle has to resolve each file against
# its own container.
from scapy.all import IP, TCP, Raw, wrpcap, Ether

def ip(s, d):
    return Ether() / IP(src=s, dst=d)

B = "BOUNDARYxyz"
part_hdr = (b"--" + B.encode() + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="part1.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n")
part_data = b"01234567"
req = (b"POST /upload HTTP/1.1\r\nHost: example.com\r\n"
       b"Content-Type: multipart/form-data; boundary=" + B.encode() + b"\r\n"
       b"Content-Length: 500\r\n\r\n" + part_hdr + part_data)
resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="download.bin"\r\n'
        b"Content-Length: 100\r\n\r\n" + b"abcdefgh")

S = 1000
S1 = S + len(req)
R = 5000
R1 = R + len(resp)

pkts = [
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="S", seq=S),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=49152, flags="SA", seq=R, ack=S + 1),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="A", seq=S + 1, ack=R + 1),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="PA", seq=S + 1,
        ack=R + 1) / Raw(load=req),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=49152, flags="PA", seq=R + 1,
        ack=S1) / Raw(load=resp),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="A", seq=S1, ack=R1),
    # no FIN: the pcap ends mid-stream in both directions
]

wrpcap("input.pcap", pkts)
